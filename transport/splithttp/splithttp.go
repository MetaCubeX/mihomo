package splithttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/log"
	"golang.org/x/net/http2"
)

func appendToPath(path string, sessionId string) string {
	if path == "" {
		return "/" + sessionId
	}
	if path[len(path)-1] == '/' {
		return path + sessionId
	}
	return path + "/" + sessionId
}

func getBaseRequest(ctx context.Context, method, urlStr string, body io.Reader, config *SplitHTTPConfig) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, err
	}
	return req, nil
}

type Conn struct {
	net.Conn
	reader io.ReadCloser
	writer io.WriteCloser
	debug  bool
	rOnce  sync.Once
	wOnce  sync.Once
}

func NewConn(base net.Conn, reader io.ReadCloser, writer io.WriteCloser, debug bool) *Conn {
	return &Conn{
		Conn:   base,
		reader: reader,
		writer: writer,
		debug:  debug,
	}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.reader == nil {
		return 0, io.EOF
	}
	n, err = c.reader.Read(b)
	if c.debug && err != nil {
		c.rOnce.Do(func() {
			log.Infoln("splithttp[conn-read] n=%d err=%v", n, err)
		})
	}
	return n, err
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.writer == nil {
		return 0, io.ErrClosedPipe
	}
	n, err = c.writer.Write(b)
	if c.debug && err != nil {
		c.wOnce.Do(func() {
			log.Infoln("splithttp[conn-write] n=%d err=%v", n, err)
		})
	}
	return n, err
}

func (c *Conn) Close() error {
	var errs []error
	if c.reader != nil {
		if err := c.reader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.writer != nil {
		if err := c.writer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := c.Conn.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func parseMode(config *SplitHTTPConfig) string {
	if config.Mode != "" && config.Mode != "auto" {
		return config.Mode
	}
	return "packet-up"
}

type connTelemetry struct {
	localAddr  string
	remoteAddr string
}

func getConnTelemetry(c net.Conn) connTelemetry {
	baseConn := c
	meta := connTelemetry{}
	if baseConn != nil {
		if l := baseConn.LocalAddr(); l != nil {
			meta.localAddr = l.String()
		}
		if r := baseConn.RemoteAddr(); r != nil {
			meta.remoteAddr = r.String()
		}
	}
	return meta
}

func logRequest(config *SplitHTTPConfig, stage string, req *http.Request, sessionID string, seqStr string, meta connTelemetry) {
	if !config.RequestLog {
		return
	}
	log.Infoln("splithttp[%s] %s %s host=%s session=%s seq=%s meta={%s} local=%s remote=%s headers={%s}",
		stage,
		req.Method,
		req.URL.String(),
		req.Host,
		sessionID,
		seqStr,
		config.MetaSummary(req),
		meta.localAddr,
		meta.remoteAddr,
		config.HeaderSummary(req),
	)
}

func logResponse(config *SplitHTTPConfig, stage string, resp *http.Response, sessionID string, seqStr string, meta connTelemetry) {
	if !config.RequestLog || resp == nil {
		return
	}
	server := resp.Header.Get("Server")
	if server == "" {
		server = "Unknown"
	}
	cfRayPart := ""
	if cfRay := resp.Header.Get("Cf-Ray"); cfRay != "" {
		cfRayPart = " cf-ray=" + cfRay
	}
	log.Infoln("splithttp[%s-resp] status=%d session=%s seq=%s actual_http=%s local=%s remote=%s server=%s%s content-length=%s",
		stage,
		resp.StatusCode,
		sessionID,
		seqStr,
		resp.Proto,
		meta.localAddr,
		meta.remoteAddr,
		server,
		cfRayPart,
		resp.Header.Get("Content-Length"),
	)
}

// PacketUpWriter splits Write calls into separate HTTP requests
type PacketUpWriter struct {
	ctx       context.Context
	client    *http.Client
	url       string
	config    *SplitHTTPConfig
	sessionId string
	seq       int64
	closed    bool
	mu        sync.Mutex
	meta      connTelemetry
}

func (w *PacketUpWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	seqStr := strconv.FormatInt(w.seq, 10)
	w.seq++
	w.mu.Unlock()

	req, err := getBaseRequest(w.ctx, w.config.GetNormalizedUplinkHTTPMethod(), w.url, nil, w.config)
	if err != nil {
		return 0, err
	}
	w.config.FillPacketRequest(req, w.sessionId, seqStr, b)
	logRequest(w.config, "packet-up", req, w.sessionId, seqStr, w.meta)

	resp, err := w.client.Do(req)
	if err != nil {
		return 0, err
	}
	logResponse(w.config, "packet-up", resp, w.sessionId, seqStr, w.meta)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("packet-up bad status: %d", resp.StatusCode)
	}

	return len(b), nil
}

func (w *PacketUpWriter) Close() error {
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	return nil
}

// StreamConn builds either Stream-One, Stream-Up/Down, or Packet-Up multiplexed flow based on configs.
func StreamConn(ctx context.Context, c net.Conn, config *SplitHTTPConfig) (net.Conn, error) {
	mode := parseMode(config)

	sessionId := ""
	if mode != "stream-one" {
		sessionId = utils.NewUUIDV4().String()
	}

	url := fmt.Sprintf("https://%s%s", config.Host, config.GetNormalizedPath())
	connMeta := getConnTelemetry(c)

	// Since c implies an underlying TLS connection ALREADY wrapped from outside, we use http2.Transport
	// with AllowHTTP to force H2 frames unencrypted down the pipe.
	rt := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			return c, nil
		},
		ReadIdleTimeout: 30 * time.Second,
		PingTimeout:     10 * time.Second,
	}

	client := &http.Client{
		Transport: rt,
	}

	if mode == "stream-one" {
		pr, pw := io.Pipe()

		req, err := getBaseRequest(ctx, config.GetNormalizedUplinkHTTPMethod(), url, pr, config)
		if err != nil {
			return nil, fmt.Errorf("create req failed: %w", err)
		}
		config.FillStreamRequest(req, sessionId)
		logRequest(config, "stream-one", req, sessionId, "", connMeta)

		respChan := make(chan *http.Response, 1)
		errChan := make(chan error, 1)

		go func() {
			resp, err := client.Do(req)
			if err != nil {
				errChan <- err
				return
			}
			respChan <- resp
		}()

		select {
		case <-errChan:
			// Fallback: Retry with HTTP/1.1 if HTTP2 failed (some servers only accept H1)
			client.Transport = &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return c, nil
				},
				ForceAttemptHTTP2: false,
			}
			go func() {
				// Must recreate Pipe to reset reader state
				pr2, pw2 := io.Pipe()
				pw = pw2
				req, _ := getBaseRequest(ctx, config.GetNormalizedUplinkHTTPMethod(), url, pr2, config)
				config.FillStreamRequest(req, sessionId)
				logRequest(config, "stream-one-retry", req, sessionId, "", connMeta)
				resp, err := client.Do(req)
				if err != nil {
					errChan <- err
					return
				}
				respChan <- resp
			}()

			select {
			case <-errChan:
				return nil, fmt.Errorf("splithttp single request failed: %w", err)
			case resp := <-respChan:
				return NewConn(c, resp.Body, pw, config.RequestLog), nil
			}

		case resp := <-respChan:
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("splithttp unexpected status code: %d", resp.StatusCode)
			}
			return NewConn(c, resp.Body, pw, config.RequestLog), nil
		case <-time.After(5 * time.Second):
			return NewConn(c, nil, pw, config.RequestLog), nil
		}
	} else {
		// Both stream-up and packet-up use a long-lived GET request for downloads.
		downReq, err := getBaseRequest(ctx, "GET", url, nil, config)
		if err != nil {
			return nil, fmt.Errorf("create stream-down req failed: %w", err)
		}
		config.FillStreamRequest(downReq, sessionId)
		logRequest(config, "stream-down", downReq, sessionId, "", connMeta)

		downRespChan := make(chan *http.Response, 1)
		downErrChan := make(chan error, 1)

		go func() {
			resp, err := client.Do(downReq)
			if err != nil {
				downErrChan <- err
				return
			}
			downRespChan <- resp
		}()

		var downstreamReader io.ReadCloser

		select {
		case err := <-downErrChan:
			return nil, fmt.Errorf("splithttp stream-down failed: %w", err)
		case resp := <-downRespChan:
			logResponse(config, "stream-down", resp, sessionId, "", connMeta)
			if resp.StatusCode != http.StatusOK {
				b, _ := io.ReadAll(resp.Body)
				return nil, fmt.Errorf("splithttp stream-down bad status code: %d, body: %s", resp.StatusCode, string(b))
			}
			downstreamReader = resp.Body
		case <-time.After(5 * time.Second):
			return nil, fmt.Errorf("splithttp stream-down timeout")
		}

		if mode == "stream-up" {
			upReader, upWriter := io.Pipe()
			upReq, err := getBaseRequest(ctx, config.GetNormalizedUplinkHTTPMethod(), url, upReader, config)
			if err != nil {
				return nil, fmt.Errorf("create stream-up req failed: %w", err)
			}
			config.FillStreamRequest(upReq, sessionId)
			logRequest(config, "stream-up", upReq, sessionId, "", connMeta)

			go func() {
				resp, _ := client.Do(upReq)
				if resp != nil && resp.Body != nil {
					resp.Body.Close()
				}
			}()

			return NewConn(c, downstreamReader, upWriter, config.RequestLog), nil
		} else if mode == "packet-up" {
			writer := &PacketUpWriter{
				ctx:       ctx,
				client:    client,
				url:       url,
				config:    config,
				sessionId: sessionId,
				meta:      connMeta,
			}
			return NewConn(c, downstreamReader, writer, config.RequestLog), nil
		}
	}

	return nil, fmt.Errorf("unsupported splithttp mode %s", mode)
}
