package sudoku

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/metacubex/mihomo/transport/sudoku/obfs/httpmask"
)

type HTTPMaskTunnelServer struct {
	cfg *ProtocolConfig
	ts  *httpmask.TunnelServer
}

func NewHTTPMaskTunnelServer(cfg *ProtocolConfig) *HTTPMaskTunnelServer {
	if cfg == nil {
		return &HTTPMaskTunnelServer{}
	}

	var ts *httpmask.TunnelServer
	if !cfg.DisableHTTPMask {
		switch strings.ToLower(strings.TrimSpace(cfg.HTTPMaskMode)) {
		case "stream", "poll", "auto":
			ts = httpmask.NewTunnelServer(httpmask.TunnelServerOptions{
				Mode:     cfg.HTTPMaskMode,
				PathRoot: cfg.HTTPMaskPathRoot,
				AuthKey:  ClientAEADSeed(cfg.Key),
			})
		}
	}
	return &HTTPMaskTunnelServer{cfg: cfg, ts: ts}
}

// WrapConn inspects an accepted TCP connection and upgrades it to an HTTP tunnel stream when needed.
//
// Returns:
//   - done=true: this TCP connection has been fully handled (e.g., stream/poll control request), caller should return
//   - done=false: handshakeConn+cfg are ready for ServerHandshake
func (s *HTTPMaskTunnelServer) WrapConn(rawConn net.Conn) (handshakeConn net.Conn, cfg *ProtocolConfig, done bool, err error) {
	if rawConn == nil {
		return nil, nil, true, fmt.Errorf("nil conn")
	}
	if s == nil {
		return rawConn, nil, false, nil
	}
	if s.ts == nil {
		return rawConn, s.cfg, false, nil
	}

	res, c, err := s.ts.HandleConn(rawConn)
	if err != nil {
		return nil, nil, true, err
	}

	switch res {
	case httpmask.HandleDone:
		return nil, nil, true, nil
	case httpmask.HandlePassThrough:
		return c, s.cfg, false, nil
	case httpmask.HandleStartTunnel:
		inner := *s.cfg
		inner.DisableHTTPMask = true
		return c, &inner, false, nil
	default:
		return nil, nil, true, nil
	}
}

type TunnelDialer func(ctx context.Context, network, addr string) (net.Conn, error)

// DialHTTPMaskTunnel dials a CDN-capable HTTP tunnel (stream/poll/auto) and returns a stream carrying raw Sudoku bytes.
func DialHTTPMaskTunnel(ctx context.Context, serverAddress string, cfg *ProtocolConfig, dial TunnelDialer, upgrade func(net.Conn) (net.Conn, error)) (net.Conn, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if cfg.DisableHTTPMask {
		return nil, fmt.Errorf("http mask is disabled")
	}
	switch strings.ToLower(strings.TrimSpace(cfg.HTTPMaskMode)) {
	case "stream", "poll", "auto":
	default:
		return nil, fmt.Errorf("http-mask-mode=%q does not use http tunnel", cfg.HTTPMaskMode)
	}
	return httpmask.DialTunnel(ctx, serverAddress, httpmask.TunnelDialOptions{
		Mode:         cfg.HTTPMaskMode,
		TLSEnabled:   cfg.HTTPMaskTLSEnabled,
		HostOverride: cfg.HTTPMaskHost,
		PathRoot:     cfg.HTTPMaskPathRoot,
		AuthKey:      ClientAEADSeed(cfg.Key),
		Upgrade:      upgrade,
		Multiplex:    cfg.HTTPMaskMultiplex,
		DialContext:  dial,
	})
}

type HTTPMaskTunnelClient struct {
	mode     string
	pathRoot string
	authKey  string
	client   *httpmask.TunnelClient
}

func NewHTTPMaskTunnelClient(serverAddress string, cfg *ProtocolConfig, dial TunnelDialer) (*HTTPMaskTunnelClient, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if cfg.DisableHTTPMask {
		return nil, fmt.Errorf("http mask is disabled")
	}
	switch strings.ToLower(strings.TrimSpace(cfg.HTTPMaskMode)) {
	case "stream", "poll", "auto":
	default:
		return nil, fmt.Errorf("http-mask-mode=%q does not use http tunnel", cfg.HTTPMaskMode)
	}
	switch strings.ToLower(strings.TrimSpace(cfg.HTTPMaskMultiplex)) {
	case "auto", "on":
	default:
		return nil, fmt.Errorf("http-mask-multiplex=%q does not enable reuse", cfg.HTTPMaskMultiplex)
	}

	c, err := httpmask.NewTunnelClient(serverAddress, httpmask.TunnelClientOptions{
		TLSEnabled:   cfg.HTTPMaskTLSEnabled,
		HostOverride: cfg.HTTPMaskHost,
		DialContext:  dial,
	})
	if err != nil {
		return nil, err
	}

	return &HTTPMaskTunnelClient{
		mode:     cfg.HTTPMaskMode,
		pathRoot: cfg.HTTPMaskPathRoot,
		authKey:  ClientAEADSeed(cfg.Key),
		client:   c,
	}, nil
}

func (c *HTTPMaskTunnelClient) Dial(ctx context.Context, upgrade func(net.Conn) (net.Conn, error)) (net.Conn, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("nil httpmask tunnel client")
	}
	return c.client.DialTunnel(ctx, httpmask.TunnelDialOptions{
		Mode:     c.mode,
		PathRoot: c.pathRoot,
		AuthKey:  c.authKey,
		Upgrade:  upgrade,
	})
}

func (c *HTTPMaskTunnelClient) CloseIdleConnections() {
	if c == nil || c.client == nil {
		return
	}
	c.client.CloseIdleConnections()
}
