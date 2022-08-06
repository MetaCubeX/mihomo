package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	tlsC "github.com/Dreamacro/clash/component/tls"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	D "github.com/miekg/dns"
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

func newDoHClient(url string, r *Resolver, params map[string]string, proxyAdapter string) *dohClient {
	useH3 := params["h3"] == "true"
	TLCConfig := tlsC.GetDefaultTLSConfig()
	var transport http.RoundTripper
	if useH3 {
		transport = &http3.RoundTripper{
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}

				ip, err := resolver.ResolveIPWithResolver(host, r)
				if err != nil {
					return nil, err
				}

				portInt, err := strconv.Atoi(port)
				if err != nil {
					return nil, err
				}

				udpAddr := net.UDPAddr{
					IP:   net.ParseIP(ip.String()),
					Port: portInt,
				}

				var conn net.PacketConn
				if proxyAdapter == "" {
					conn, err = dialer.ListenPacket(ctx, "udp", "")
					if err != nil {
						return nil, err
					}
				} else {
					if wrapConn, err := dialContextExtra(ctx, proxyAdapter, "udp", ip, port); err == nil {
						if pc, ok := wrapConn.(*wrapPacketConn); ok {
							conn = pc
						} else {
							return nil, fmt.Errorf("conn isn't wrapPacketConn")
						}
					} else {
						return nil, err
					}
				}

				return quic.DialEarlyContext(ctx, conn, &udpAddr, host, tlsCfg, cfg)
			},
			TLSClientConfig: TLCConfig,
		}
	} else {
		transport = &http.Transport{
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
			TLSClientConfig: TLCConfig,
		}
	}

	return &dohClient{
		url:       url,
		transport: transport,
	}
}
