/*
Copyright (C) 2026 by saba <contact me via issue>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
*/
package httpmask

import (
	"context"
	"fmt"
	mrand "math/rand"
	"net"
	"strings"
	"time"

	"github.com/metacubex/http"
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

func multiplexEnabled(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto", "on":
		return true
	default:
		return false
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
	// Multiplex controls reuse of HTTP keep-alive / HTTP/2 connections.
	Multiplex string
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
		streamCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
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
		streamCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
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

var (
	dialStreamFn = dialStream
	dialPollFn   = dialPoll
)

func applyTunnelHeaders(h http.Header, host string, mode TunnelMode) {
	if h == nil {
		return
	}
	r := rngPool.Get().(*mrand.Rand)
	ua := userAgents[r.Intn(len(userAgents))]
	accept := accepts[r.Intn(len(accepts))]
	lang := acceptLanguages[r.Intn(len(acceptLanguages))]
	rngPool.Put(r)
	h.Set("User-Agent", ua)
	h.Set("Accept", accept)
	h.Set("Accept-Language", lang)
	h.Set("Cache-Control", "no-cache")
	h.Set("Pragma", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("Host", host)
	h.Set("X-Sudoku-Tunnel", string(mode))
}
