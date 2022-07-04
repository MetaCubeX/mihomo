package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	D "github.com/miekg/dns"
	"go.uber.org/atomic"
	"io"
	"net"
	"net/http"
	"strconv"
)

const (
	// dotMimeType is the DoH mimetype that should be used.
	dotMimeType = "application/dns-message"
)

type dohClient struct {
	url          string
	proxyAdapter string
	transport    *http.Transport
	h3Transport  *http3.RoundTripper
	supportH3    *atomic.Bool
	firstTest    *atomic.Bool
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
	if dc.supportH3.Load() {
		msg, err = dc.doRequestWithTransport(req, dc.h3Transport)
		if err != nil {
			if dc.firstTest.CAS(true, false) {
				dc.supportH3.Store(false)
				_ = dc.h3Transport.Close()
				dc.h3Transport = nil
			}
		} else {
			if dc.firstTest.CAS(true, false) {
				dc.supportH3.Store(true)
				dc.transport.CloseIdleConnections()
				dc.transport = nil
			}
		}
	} else {
		msg, err = dc.doRequestWithTransport(req, dc.transport)
	}

	return
}

func (dc *dohClient) doRequestWithTransport(req *http.Request, transport http.RoundTripper) (*D.Msg, error) {
	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		if err != nil {
			return nil, err
		}
	}

	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	msg := &D.Msg{}
	err = msg.Unpack(buf)
	return msg, err
}

func newDoHClient(url string, r *Resolver, preferH3 bool, proxyAdapter string) *dohClient {
	return &dohClient{
		url:          url,
		proxyAdapter: proxyAdapter,
		transport: &http.Transport{
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
		},

		h3Transport: &http3.RoundTripper{
			Dial: func(ctx context.Context, network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
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
		},
		supportH3: atomic.NewBool(preferH3),
		firstTest: atomic.NewBool(true),
	}
}
