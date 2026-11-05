package httpmask

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/randv2"
)

type TunnelMode string

const (
	TunnelModeLegacy TunnelMode = "legacy"
	TunnelModeStream TunnelMode = "stream"
	TunnelModePoll   TunnelMode = "poll"
	TunnelModeAuto   TunnelMode = "auto"
	TunnelModeWS     TunnelMode = "ws"
)

func normalizeTunnelMode(mode string) TunnelMode {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", string(TunnelModeLegacy):
		return TunnelModeLegacy
	case string(TunnelModeStream):
		return TunnelModeStream
	case string(TunnelModePoll):
		return TunnelModePoll
	case string(TunnelModeAuto):
		return TunnelModeAuto
	case string(TunnelModeWS):
		return TunnelModeWS
	default:
		return TunnelModeLegacy
	}
}

type HandleResult int

const (
	HandlePassThrough HandleResult = iota
	HandleStartTunnel
	HandleDone
)

type TunnelDialOptions struct {
	Mode         string
	TLSEnabled   bool
	HostOverride string
	PathRoot     string
	// AuthKey is used only for WebSocket anti-probing authentication. Stream and
	// poll use the authenticated Sudoku session token and upload sequence.
	AuthKey        string
	EarlyHandshake *ClientEarlyHandshake
	Upgrade        func(raw net.Conn) (net.Conn, error)
	// DialContext is required so embedders can preserve their routing and proxy behavior.
	DialContext func(context.Context, string, string) (net.Conn, error)
}

type TunnelClientOptions struct {
	TLSEnabled   bool
	HostOverride string
	DialContext  func(context.Context, string, string) (net.Conn, error)
	MaxIdleConns int
}

type TunnelClient struct {
	client *tunnelHTTPClient
	target httpClientTarget
}

func NewTunnelClient(serverAddress string, opts TunnelClientOptions) (*TunnelClient, error) {
	maxIdle := opts.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = 32
	}
	client, target, err := newHTTPClient(serverAddress, opts.TLSEnabled, opts.HostOverride, opts.DialContext, maxIdle)
	if err != nil {
		return nil, err
	}
	return &TunnelClient{client: client, target: target}, nil
}

func (c *TunnelClient) CloseIdleConnections() {
	if c == nil || c.client == nil {
		return
	}
	c.client.client.CloseIdleConnections()
	c.client.transport.clearIdle()
}

// Close releases the client and its preconnected sockets permanently.
func (c *TunnelClient) Close() {
	if c == nil || c.client == nil {
		return
	}
	c.client.transport.close()
}

func (c *TunnelClient) DialTunnel(ctx context.Context, opts TunnelDialOptions) (net.Conn, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("nil tunnel client")
	}
	mode := normalizeTunnelMode(opts.Mode)
	if mode == TunnelModeLegacy {
		return nil, fmt.Errorf("legacy mode does not use http tunnel")
	}

	client := c.client.client
	switch mode {
	case TunnelModeStream:
		return dialStreamWithClient(ctx, client, c.client.transport.dialer, c.target, opts)
	case TunnelModePoll:
		return dialPollWithClient(ctx, client, c.client.transport.dialer, c.target, opts)
	case TunnelModeAuto:
		streamCtx, cancel := autoProbeContext(ctx)
		conn, streamErr := dialStreamWithClient(streamCtx, client, c.client.transport.dialer, c.target, opts)
		cancel()
		if streamErr == nil {
			return conn, nil
		}
		conn, pollErr := dialPollWithClient(ctx, client, c.client.transport.dialer, c.target, opts)
		if pollErr == nil {
			return conn, nil
		}
		return nil, fmt.Errorf("auto tunnel failed: stream: %v; poll: %w", streamErr, pollErr)
	case TunnelModeWS:
		return nil, fmt.Errorf("ws mode does not support TunnelClient reuse")
	default:
		return dialStreamWithClient(ctx, client, c.client.transport.dialer, c.target, opts)
	}
}

// DialTunnel establishes a bidirectional raw Sudoku stream over HTTPMask.
func DialTunnel(ctx context.Context, serverAddress string, opts TunnelDialOptions) (net.Conn, error) {
	mode := normalizeTunnelMode(opts.Mode)
	if mode == TunnelModeLegacy {
		return nil, fmt.Errorf("legacy mode does not use http tunnel")
	}

	switch mode {
	case TunnelModeStream:
		return dialStreamFn(ctx, serverAddress, opts)
	case TunnelModePoll:
		return dialPollFn(ctx, serverAddress, opts)
	case TunnelModeWS:
		return dialWS(ctx, serverAddress, opts)
	case TunnelModeAuto:
		streamCtx, cancel := autoProbeContext(ctx)
		conn, streamErr := dialStreamFn(streamCtx, serverAddress, opts)
		cancel()
		if streamErr == nil {
			return conn, nil
		}
		conn, pollErr := dialPollFn(ctx, serverAddress, opts)
		if pollErr == nil {
			return conn, nil
		}
		return nil, fmt.Errorf("auto tunnel failed: stream: %v; poll: %w", streamErr, pollErr)
	default:
		return dialStreamFn(ctx, serverAddress, opts)
	}
}

const autoProbeTimeout = 20 * time.Second

func autoProbeContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, autoProbeTimeout)
}

var (
	dialStreamFn = dialStream
	dialPollFn   = dialPoll
)

// Header values are prebuilt and shared by every request: the transport only reads them, and a fresh []string per
// header would be most of what applying the profile costs.
var (
	userAgentValues      = singleValues(userAgents)
	acceptValues         = singleValues(accepts)
	acceptLanguageValues = singleValues(acceptLanguages)
	noCacheValue         = []string{"no-cache"}
	keepAliveValue       = []string{"keep-alive"}
	tunnelModeValues     = map[TunnelMode][]string{
		TunnelModeStream: {string(TunnelModeStream)},
		TunnelModePoll:   {string(TunnelModePoll)},
	}
)

func singleValues(vs []string) [][]string {
	out := make([][]string, len(vs))
	for i, v := range vs {
		out[i] = []string{v}
	}
	return out
}

func applyTunnelHeaders(h http.Header, host string, mode TunnelMode) {
	h["User-Agent"] = userAgentValues[randv2.IntN(len(userAgentValues))]
	h["Accept"] = acceptValues[randv2.IntN(len(acceptValues))]
	h["Accept-Language"] = acceptLanguageValues[randv2.IntN(len(acceptLanguageValues))]
	h["Cache-Control"] = noCacheValue
	h["Pragma"] = noCacheValue
	h["Connection"] = keepAliveValue
	h["Host"] = []string{host}
	modeValue, ok := tunnelModeValues[mode]
	if !ok {
		modeValue = []string{string(mode)}
	}
	h["X-Sudoku-Tunnel"] = modeValue
}
