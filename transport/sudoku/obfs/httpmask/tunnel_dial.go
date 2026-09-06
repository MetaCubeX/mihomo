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
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/metacubex/http"
	"github.com/metacubex/tls"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/ca"
)

const (
	tunnelEarlyDataQueryKey   = "ed"
	tunnelEarlyDataHeader     = "X-Sudoku-Early"
	tunnelStreamEOFHeader     = "X-Sudoku-Stream-EOF"
	tunnelUploadSequenceQuery = "seq"
	tunnelUploadSequenceCap   = "upload-seq"
	tunnelPreconnectCount     = 3
	tunnelTLSHandshakeTimeout = 10 * time.Second
)

type authorizeResponse struct {
	token        string
	earlyPayload []byte
}

func canonicalHeaderHost(urlHost, scheme string) string {
	host, port, err := net.SplitHostPort(urlHost)
	if err != nil {
		return urlHost
	}

	defaultPort := ""
	switch scheme {
	case "https":
		defaultPort = "443"
	case "http":
		defaultPort = "80"
	}
	if defaultPort == "" || port != defaultPort {
		return urlHost
	}

	// If we strip the port from an IPv6 literal, re-add brackets to keep the Host header valid.
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func sessionPreconnectCount() int {
	// Three connections overlap authorization, the initial pull, and the first
	// upload without waiting for another WAN round trip before mux is usable.
	return tunnelPreconnectCount
}

func parseAuthorizeResponse(body []byte) (*authorizeResponse, error) {
	s := strings.TrimSpace(string(body))
	idx := strings.Index(s, "token=")
	if idx < 0 {
		return nil, errors.New("missing token")
	}
	s = s[idx+len("token="):]
	if s == "" {
		return nil, errors.New("empty token")
	}
	// Token is base64.RawURLEncoding (A-Z a-z 0-9 - _). Strip any trailing bytes (e.g. from CDN compression).
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			b.WriteByte(c)
			continue
		}
		break
	}
	token := b.String()
	if token == "" {
		return nil, errors.New("empty token")
	}
	out := &authorizeResponse{token: token}
	if earlyLine := findAuthorizeField(body, "ed="); earlyLine != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(earlyLine)
		if err != nil {
			return nil, fmt.Errorf("decode early authorize payload failed: %w", err)
		}
		out.earlyPayload = decoded
	}
	if findAuthorizeField(body, "cap=") != tunnelUploadSequenceCap {
		return nil, errors.New("server does not support HTTPMask v0.5 upload sequencing")
	}
	return out, nil
}

func findAuthorizeField(body []byte, prefix string) string {
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func setEarlyDataQuery(rawURL string, payload []byte) (string, error) {
	if len(payload) == 0 {
		return rawURL, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(tunnelEarlyDataQueryKey, base64.RawURLEncoding.EncodeToString(payload))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func parseEarlyDataQuery(u *url.URL) ([]byte, error) {
	if u == nil {
		return nil, nil
	}
	val := strings.TrimSpace(u.Query().Get(tunnelEarlyDataQueryKey))
	if val == "" {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(val)
}

type sessionDialInfo struct {
	client     *http.Client
	owner      *tunnelHTTPTransport
	pushURL    string
	pullURL    string
	finURL     string
	closeURL   string
	headerHost string
}

func uploadURL(rawURL string, sequence uint64) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(tunnelUploadSequenceQuery, strconv.FormatUint(sequence, 10))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

type tunnelHTTPTransport struct {
	transport *http.Transport
	dialer    *preconnectDialer
}

func (t *tunnelHTTPTransport) close() {
	if t == nil {
		return
	}
	if t.transport != nil {
		t.transport.CloseIdleConnections()
	}
	if t.dialer != nil {
		t.dialer.close()
	}
}

func (t *tunnelHTTPTransport) clearIdle() {
	if t == nil {
		return
	}
	if t.transport != nil {
		t.transport.CloseIdleConnections()
	}
	if t.dialer != nil {
		t.dialer.clearIdle()
	}
}

type tunnelHTTPClient struct {
	client    *http.Client
	transport *tunnelHTTPTransport
}

func (c *tunnelHTTPClient) preconnect(ctx context.Context, req *http.Request, count int) context.CancelFunc {
	if c == nil || c.transport == nil || c.transport.transport == nil || c.transport.dialer == nil ||
		req == nil || req.URL == nil || count <= 0 {
		return func() {}
	}

	if proxy := c.transport.transport.Proxy; proxy != nil {
		proxyURL, err := proxy(req)
		if err != nil || proxyURL != nil {
			return func() {}
		}
	}
	return c.transport.dialer.preconnect(ctx, req.URL.Scheme == "https", count)
}

type httpClientTarget struct {
	scheme     string
	urlHost    string
	headerHost string
}

func newHTTPClient(serverAddress string, tlsEnabled bool, hostOverride string, dial func(context.Context, string, string) (net.Conn, error), maxIdleConns int) (*tunnelHTTPClient, httpClientTarget, error) {
	if dial == nil {
		return nil, httpClientTarget{}, errors.New("httpmask: DialContext is nil")
	}
	scheme, urlHost, dialAddr, serverName, err := normalizeHTTPDialTarget(serverAddress, tlsEnabled, hostOverride)
	if err != nil {
		return nil, httpClientTarget{}, err
	}
	var transportTLSConfig, dialerTLSConfig *tls.Config
	if scheme == "https" {
		transportTLSConfig, err = ca.GetTLSConfig(ca.Option{TLSConfig: &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
		}})
		if err != nil {
			return nil, httpClientTarget{}, err
		}
		dialerTLSConfig = transportTLSConfig.Clone()
	}
	dialer := newPreconnectDialer(urlHost, dialAddr, serverName, dialerTLSConfig, dial)
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     scheme == "https",
		DisableCompression:    true,
		MaxIdleConns:          maxIdleConns,
		MaxIdleConnsPerHost:   maxIdleConns,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		TLSHandshakeTimeout:   tunnelTLSHandshakeTimeout,
		DialContext:           dialer.dialContext,
	}
	if scheme == "https" {
		transport.TLSClientConfig = transportTLSConfig
		transport.DialTLSContext = dialer.dialTLSContext
	}
	tunnelTransport := &tunnelHTTPTransport{transport: transport, dialer: dialer}
	return &tunnelHTTPClient{
		client:    &http.Client{Transport: transport},
		transport: tunnelTransport,
	}, httpClientTarget{scheme: scheme, urlHost: urlHost, headerHost: canonicalHeaderHost(urlHost, scheme)}, nil
}

func dialSession(ctx context.Context, serverAddress string, opts TunnelDialOptions, mode TunnelMode) (*sessionDialInfo, error) {
	httpClient, target, err := newHTTPClient(serverAddress, opts.TLSEnabled, opts.HostOverride, opts.DialContext, 32)
	if err != nil {
		return nil, err
	}
	// One-shot callers do not retain the transport long enough to benefit from
	// speculative sockets. Avoid creating a connection burst during concurrent
	// authorization; reused TunnelClients keep the three-connection fast path.
	info, err := dialSessionWithClient(ctx, httpClient.client, httpClient.transport.dialer, target, mode, opts, 0)
	if err != nil {
		httpClient.transport.close()
		return nil, err
	}
	// The one-shot DialTunnel owns its HTTP transport. Reused TunnelClients
	// leave ownership nil so closing one session cannot tear down its siblings.
	info.owner = httpClient.transport
	return info, nil
}

func dialSessionWithClient(ctx context.Context, client *http.Client, dialer *preconnectDialer, target httpClientTarget, mode TunnelMode, opts TunnelDialOptions, preconnectCount int) (*sessionDialInfo, error) {
	if client == nil {
		return nil, errors.New("httpmask: HTTP client is nil")
	}
	headerHost := target.headerHost
	scheme, urlHost := target.scheme, target.urlHost
	var err error

	authorizeURL := (&url.URL{Scheme: scheme, Host: urlHost, Path: joinPathRoot(opts.PathRoot, "/session")}).String()
	if opts.EarlyHandshake != nil && len(opts.EarlyHandshake.RequestPayload) > 0 {
		authorizeURL, err = setEarlyDataQuery(authorizeURL, opts.EarlyHandshake.RequestPayload)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authorizeURL, nil)
	if err != nil {
		return nil, err
	}
	req.Host = headerHost
	applyTunnelHeaders(req.Header, headerHost, mode)

	// Overlap authorization, initial pull, and initial push connection handshakes.
	// Keeping this to three avoids adding an extra WAN RTT before mux can open
	// its first logical stream.
	if dialer != nil {
		cancelPreconnect := dialer.preconnect(ctx, scheme == "https", preconnectCount)
		defer cancelPreconnect()
	}

	var resp *http.Response
	backoff := 50 * time.Millisecond
	for attempt := 0; attempt < 3; attempt++ {
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		if attempt == 2 || !isRetryableHTTPTransportError(err) {
			return nil, err
		}
		closeIdleConnections(client)
		if retryErr := waitRetry(ctx.Done(), nil, backoff); retryErr != nil {
			return nil, retryErr
		}
		backoff = nextBackoff(backoff, 50*time.Millisecond, 500*time.Millisecond)
		// A request with a consumed transport connection must be rebuilt before
		// retrying; GET authorization is idempotent.
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, authorizeURL, nil)
		if err != nil {
			return nil, err
		}
		req.Host = headerHost
		applyTunnelHeaders(req.Header, headerHost, mode)
	}
	if resp == nil {
		return nil, errors.New("httpmask: authorization returned no response")
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s authorize bad status: %s (%s)", mode, resp.Status, strings.TrimSpace(string(bodyBytes)))
	}

	authResp, err := parseAuthorizeResponse(bodyBytes)
	if err != nil {
		return nil, fmt.Errorf("%s authorize failed: %w", mode, err)
	}
	token := authResp.token
	if token == "" {
		return nil, fmt.Errorf("%s authorize empty token", mode)
	}
	if opts.EarlyHandshake != nil && len(authResp.earlyPayload) > 0 && opts.EarlyHandshake.HandleResponse != nil {
		if err := opts.EarlyHandshake.HandleResponse(authResp.earlyPayload); err != nil {
			return nil, err
		}
	}

	pushURL := (&url.URL{Scheme: scheme, Host: urlHost, Path: joinPathRoot(opts.PathRoot, "/api/v1/upload"), RawQuery: "token=" + url.QueryEscape(token)}).String()
	pullURL := (&url.URL{Scheme: scheme, Host: urlHost, Path: joinPathRoot(opts.PathRoot, "/stream"), RawQuery: "token=" + url.QueryEscape(token)}).String()
	finURL := (&url.URL{Scheme: scheme, Host: urlHost, Path: joinPathRoot(opts.PathRoot, "/api/v1/upload"), RawQuery: "token=" + url.QueryEscape(token) + "&fin=1"}).String()
	closeURL := (&url.URL{Scheme: scheme, Host: urlHost, Path: joinPathRoot(opts.PathRoot, "/api/v1/upload"), RawQuery: "token=" + url.QueryEscape(token) + "&close=1"}).String()
	return &sessionDialInfo{
		client:     client,
		pushURL:    pushURL,
		pullURL:    pullURL,
		finURL:     finURL,
		closeURL:   closeURL,
		headerHost: headerHost,
	}, nil
}

func sendSessionControl(client *http.Client, controlURL, headerHost string, mode TunnelMode) error {
	const maxAttempts = 3

	if client == nil {
		return errors.New("session control client is nil")
	}
	if controlURL == "" || headerHost == "" {
		return errors.New("session control endpoint is empty")
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		lastErr error
		backoff = 50 * time.Millisecond
	)
	for attempt := 0; attempt < maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(closeCtx, http.MethodPost, controlURL, nil)
		if err != nil {
			return err
		}
		req.Host = headerHost
		applyTunnelHeaders(req.Header, headerHost, mode)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if closeCtx.Err() == nil && (isDialError(err) || isRetryableHTTPTransportError(err) || errors.Is(err, context.DeadlineExceeded)) && attempt+1 < maxAttempts {
				if err := waitRetry(closeCtx.Done(), nil, backoff); err != nil {
					return err
				}
				backoff *= 2
				continue
			}
			return err
		}
		if resp == nil {
			lastErr = io.ErrUnexpectedEOF
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
				return nil
			}
			lastErr = statusError(resp)
			if isRetryableStatusCode(resp.StatusCode) && attempt+1 < maxAttempts {
				if err := waitRetry(closeCtx.Done(), nil, backoff); err != nil {
					return err
				}
				backoff *= 2
				continue
			}
			return lastErr
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("session control failed")
	}
	return lastErr
}

func bestEffortCloseSession(client *http.Client, closeURL, headerHost string, mode TunnelMode) {
	_ = sendSessionControl(client, closeURL, headerHost, mode)
}

func normalizeHTTPDialTarget(serverAddress string, tlsEnabled bool, hostOverride string) (scheme, urlHost, dialAddr, serverName string, err error) {
	host, port, err := net.SplitHostPort(serverAddress)
	if err != nil {
		return "", "", "", "", fmt.Errorf("invalid server address %q: %w", serverAddress, err)
	}

	if hostOverride != "" {
		// Allow "example.com" or "example.com:443"
		if h, p, splitErr := net.SplitHostPort(hostOverride); splitErr == nil {
			if h != "" {
				hostOverride = h
			}
			if p != "" {
				port = p
			}
		}
		serverName = hostOverride
		urlHost = net.JoinHostPort(hostOverride, port)
	} else {
		serverName = host
		urlHost = net.JoinHostPort(host, port)
	}

	if tlsEnabled {
		scheme = "https"
	} else {
		scheme = "http"
	}

	dialAddr = net.JoinHostPort(host, port)
	return scheme, urlHost, dialAddr, trimPortForHost(serverName), nil
}
