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
	return newHTTPMaskTunnelServer(cfg, false)
}

func NewHTTPMaskTunnelServerWithFallback(cfg *ProtocolConfig) *HTTPMaskTunnelServer {
	return newHTTPMaskTunnelServer(cfg, true)
}

func newHTTPMaskTunnelServer(cfg *ProtocolConfig, passThroughOnReject bool) *HTTPMaskTunnelServer {
	if cfg == nil {
		return &HTTPMaskTunnelServer{}
	}

	var ts *httpmask.TunnelServer
	if !cfg.DisableHTTPMask {
		switch strings.ToLower(strings.TrimSpace(cfg.HTTPMaskMode)) {
		case "stream", "poll", "auto", "ws":
			ts = httpmask.NewTunnelServer(httpmask.TunnelServerOptions{
				Mode:     cfg.HTTPMaskMode,
				PathRoot: cfg.HTTPMaskPathRoot,
				AuthKey:  ServerAEADSeed(cfg.Key),
				// When upstream fallback is enabled, preserve rejected HTTP requests for the caller.
				PassThroughOnReject: passThroughOnReject,
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
		// HTTPMask tunnel modes (stream/poll/auto/ws) add extra round trips before the first
		// handshake bytes can reach ServerHandshake, especially under high concurrency.
		// Bump the handshake timeout for tunneled conns to avoid flaky timeouts while keeping
		// the default strict for raw TCP handshakes.
		const minTunneledHandshakeTimeoutSeconds = 15
		if inner.HandshakeTimeoutSeconds <= 0 || inner.HandshakeTimeoutSeconds < minTunneledHandshakeTimeoutSeconds {
			inner.HandshakeTimeoutSeconds = minTunneledHandshakeTimeoutSeconds
		}
		return c, &inner, false, nil
	default:
		return nil, nil, true, nil
	}
}

type TunnelDialer func(ctx context.Context, network, addr string) (net.Conn, error)

// DialHTTPMaskTunnel dials a CDN-capable HTTP tunnel (stream/poll/auto/ws) and returns a stream carrying raw Sudoku bytes.
func DialHTTPMaskTunnel(ctx context.Context, serverAddress string, cfg *ProtocolConfig, dial TunnelDialer, upgrade func(net.Conn) (net.Conn, error)) (net.Conn, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if cfg.DisableHTTPMask {
		return nil, fmt.Errorf("http mask is disabled")
	}
	switch strings.ToLower(strings.TrimSpace(cfg.HTTPMaskMode)) {
	case "stream", "poll", "auto", "ws":
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
