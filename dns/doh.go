package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	tls2 "github.com/Dreamacro/clash/component/tls"
	"github.com/Dreamacro/clash/log"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	D "github.com/miekg/dns"
	"go.uber.org/atomic"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
)

const (
	// dotMimeType is the DoH mimetype that should be used.
	dotMimeType = "application/dns-message"
)

type dohClient struct {
	url       string
	transport http.RoundTripper
}

func (dc *dohClient) Exchange(m *D.Msg) (msg *D.Msg, err error) {
	return dc.ExchangeContext(context.Background(), m)
}

func (dc *dohClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	// https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
	// In order to maximize cache friendliness, SHOULD use a DNS ID of 0 in every DNS request.
	newM := *m
	newM.Id = 0
	req, err := dc.newRequest(&newM)
	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)
	msg, err = dc.doRequest(req)
	if err == nil {
		msg.Id = m.Id
	}
	return
}

// newRequest returns a new DoH request given a dns.Msg.
func (dc *dohClient) newRequest(m *D.Msg) (*http.Request, error) {
	buf, err := m.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, dc.url, bytes.NewReader(buf))
	if err != nil {
		return req, err
	}

	req.Header.Set("content-type", dotMimeType)
	req.Header.Set("accept", dotMimeType)
	return req, nil
}

func (dc *dohClient) doRequest(req *http.Request) (msg *D.Msg, err error) {
	client := &http.Client{Transport: dc.transport}
	resp, err := client.Do(req)
	if err != nil {
		log.Errorln("doh %v", err)
		return nil, err
	}

	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	msg = &D.Msg{}
	err = msg.Unpack(buf)
	return msg, err
}

func newDoHClient(url string, r *Resolver, preferH3 bool, proxyAdapter string) *dohClient {
	return &dohClient{
		url:       url,
		transport: newDohTransport(r, preferH3, proxyAdapter),
	}
}

type dohTransport struct {
	*http.Transport
	h3       *http3.RoundTripper
	preferH3 bool
	canUseH3 atomic.Bool
}

func newDohTransport(r *Resolver, preferH3 bool, proxyAdapter string) *dohTransport {
	dohT := &dohTransport{
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}

				ip, err := resolver.ResolveIPWithResolver(host, r)
				if err != nil {
					return nil, err
				}

				if proxyAdapter == "" {
					return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
				} else {
					return dialContextExtra(ctx, proxyAdapter, "tcp", ip, port)
				}
			},
			TLSClientConfig: tls2.GetDefaultTLSConfig(),
		},
		preferH3: preferH3,
	}

	dohT.canUseH3.Store(preferH3)
	if preferH3 {
		dohT.h3 = &http3.RoundTripper{
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}

				ip, err := resolver.ResolveIPWithResolver(host, r)
				if err != nil {
					return nil, err
				}

				if proxyAdapter == "" {
					return quic.DialAddrEarlyContext(ctx, net.JoinHostPort(ip.String(), port), tlsCfg, cfg)
				} else {
					if conn, err := dialContextExtra(ctx, proxyAdapter, "udp", ip, port); err == nil {
						portInt, err := strconv.Atoi(port)
						if err != nil {
							return nil, err
						}

						udpAddr := net.UDPAddr{
							IP:   net.ParseIP(ip.String()),
							Port: portInt,
						}

						return quic.DialEarlyContext(ctx, conn.(net.PacketConn), &udpAddr, host, tlsCfg, cfg)
					} else {
						return nil, err
					}
				}
			},
			TLSClientConfig: tls2.GetDefaultTLSConfig(),
		}
	}

	return dohT
}

func (doh *dohTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	var bodyBytes []byte
	var h3Err bool
	var fallbackErr bool
	defer func() {
		if doh.preferH3 && (h3Err || fallbackErr) {
			doh.canUseH3.Store(doh.preferH3 && (!h3Err || fallbackErr))
		}
	}()

	if req.Body != nil {
		bodyBytes, err = ioutil.ReadAll(req.Body)
	}

	req.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))
	if doh.canUseH3.Load() {
		resp, err = doh.h3.RoundTrip(req)
		h3Err = err != nil
		if !h3Err {
			return resp, err
		} else {
			req.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	resp, err = doh.Transport.RoundTrip(req)
	fallbackErr = err != nil
	if fallbackErr {
		return resp, err
	}

	return resp, err
}
