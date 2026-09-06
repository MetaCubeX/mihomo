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
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/metacubex/http"
	"io"
	"net"
	"sync/atomic"
	"time"
)

type pollConn struct {
	queuedConn
	readiness *tunnelReadiness

	ctx    context.Context
	cancel context.CancelFunc

	client     *http.Client
	pushURL    string
	pullURL    string
	finURL     string
	closeURL   string
	headerHost string
	uploadSeq  atomic.Uint64
}

func (c *pollConn) closeWithError(err error) error {
	_ = c.queuedConn.closeWithError(err)
	if c.cancel != nil {
		c.cancel()
	}
	bestEffortCloseSession(c.client, c.closeURL, c.headerHost, TunnelModePoll)
	return nil
}

func (c *pollConn) Close() error {
	return c.closeWithError(io.ErrClosedPipe)
}

func dialPoll(ctx context.Context, serverAddress string, opts TunnelDialOptions) (net.Conn, error) {
	info, err := dialSession(ctx, serverAddress, opts, TunnelModePoll)
	if err != nil {
		return nil, err
	}
	return newPollConn(info, opts)
}

func dialPollWithClient(ctx context.Context, client *http.Client, dialer *preconnectDialer, target httpClientTarget, opts TunnelDialOptions) (net.Conn, error) {
	info, err := dialSessionWithClient(ctx, client, dialer, target, TunnelModePoll, opts)
	if err != nil {
		return nil, err
	}
	return newPollConn(info, opts)
}

func newPollConn(info *sessionDialInfo, opts TunnelDialOptions) (net.Conn, error) {
	if info == nil {
		return nil, fmt.Errorf("httpmask: nil session")
	}

	connCtx, cancel := context.WithCancel(context.Background())
	c := &pollConn{
		ctx:        connCtx,
		cancel:     cancel,
		readiness:  newTunnelReadiness(),
		client:     info.client,
		pushURL:    info.pushURL,
		pullURL:    info.pullURL,
		finURL:     info.finURL,
		closeURL:   info.closeURL,
		headerHost: info.headerHost,
		queuedConn: newQueuedConn(),
	}

	go c.pullLoop()
	go c.pushLoop()
	outConn := net.Conn(c)
	if opts.EarlyHandshake != nil && opts.EarlyHandshake.WrapConn != nil && (opts.EarlyHandshake.Ready == nil || opts.EarlyHandshake.Ready()) {
		upgraded, err := opts.EarlyHandshake.WrapConn(c)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		if upgraded != nil {
			outConn = upgraded
		}
		return wrapReadyTunnelConn(outConn, c.waitReady), nil
	}
	if opts.Upgrade != nil {
		upgraded, err := opts.Upgrade(c)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		if upgraded != nil {
			outConn = upgraded
		}
	}
	return wrapReadyTunnelConn(outConn, c.waitReady), nil
}

func (c *pollConn) waitReady(ctx context.Context) error {
	if err := c.readiness.wait(ctx, c.closed, c.closedErr); err != nil {
		return err
	}
	return nil
}

func (c *pollConn) pullLoop() {
	const (
		maxDialRetry = -1
		minBackoff   = 10 * time.Millisecond
		maxBackoff   = 250 * time.Millisecond
	)

	var (
		dialRetry int
		backoff   = minBackoff
	)
	for {
		select {
		case <-c.closed:
			return
		default:
		}

		req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.pullURL, nil)
		if err != nil {
			_ = c.closeWithError(err)
			return
		}
		req.Host = c.headerHost
		applyTunnelHeaders(req.Header, c.headerHost, TunnelModePoll)

		resp, err := c.client.Do(req)
		if err != nil {
			if (isDialError(err) || isRetryableHTTPTransportError(err)) && (maxDialRetry < 0 || dialRetry < maxDialRetry) {
				dialRetry++
				closeIdleConnections(c.client)
				select {
				case <-time.After(backoff):
				case <-c.closed:
					return
				}
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
			_ = c.closeWithError(fmt.Errorf("poll pull request failed: %w", err))
			return
		}
		dialRetry = 0
		backoff = minBackoff

		if resp.StatusCode != http.StatusOK {
			if isRetryableStatusCode(resp.StatusCode) && (maxDialRetry < 0 || dialRetry < maxDialRetry) {
				dialRetry++
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
				_ = resp.Body.Close()
				closeIdleConnections(c.client)
				select {
				case <-time.After(backoff):
				case <-c.closed:
					return
				}
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
			_ = resp.Body.Close()
			_ = c.closeWithError(fmt.Errorf("poll pull bad status: %s", resp.Status))
			return
		}
		c.readiness.markPullReady()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			payload := make([]byte, base64.StdEncoding.DecodedLen(len(line)))
			n, err := base64.StdEncoding.Decode(payload, line)
			if err != nil {
				_ = resp.Body.Close()
				_ = c.closeWithError(fmt.Errorf("poll pull decode failed: %w", err))
				return
			}
			select {
			case c.rxc <- payload[:n]:
			case <-c.closed:
				_ = resp.Body.Close()
				return
			}
		}
		_ = resp.Body.Close()
		if err := scanner.Err(); err != nil {
			if isRetryableHTTPTransportError(err) {
				closeIdleConnections(c.client)
				continue
			}
			_ = c.closeWithError(fmt.Errorf("poll pull scan failed: %w", err))
			return
		}
		if resp.Trailer.Get(tunnelStreamEOFHeader) == "1" {
			c.markReadEOF()
			return
		}
	}
}

func (c *pollConn) pushLoop() {
	const (
		maxBatchBytes   = 64 * 1024
		flushInterval   = 5 * time.Millisecond
		maxLineRawBytes = 16 * 1024
		maxDialRetry    = -1
		minBackoff      = 10 * time.Millisecond
		maxBackoff      = 250 * time.Millisecond
	)

	var (
		buf        bytes.Buffer
		encoded    = make([]byte, base64.StdEncoding.EncodedLen(maxLineRawBytes)+1)
		pendingRaw int
		timer      = time.NewTimer(flushInterval)
		writeErr   error
	)
	defer timer.Stop()
	defer func() { c.completeWrite(writeErr) }()

	fail := func(err error) {
		writeErr = err
		_ = c.closeWithError(err)
	}

	flush := func() error {
		if buf.Len() == 0 {
			return nil
		}
		sequence := c.uploadSeq.Add(1)
		requestURL, err := uploadURL(c.pushURL, sequence)
		if err != nil {
			return err
		}
		payload := append([]byte(nil), buf.Bytes()...)

		if err := retryDial(c.closed, c.closedErr, maxDialRetry, minBackoff, maxBackoff, func() error {
			reqCtx, cancel := context.WithTimeout(c.ctx, 20*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, requestURL, bytes.NewReader(payload))
			if err != nil {
				return err
			}
			req.Host = c.headerHost
			applyTunnelHeaders(req.Header, c.headerHost, TunnelModePoll)
			req.Header.Set("Content-Type", "text/plain")

			resp, err := c.client.Do(req)
			if err != nil {
				closeIdleConnections(c.client)
				return err
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				err = statusError(resp)
				if isRetryableHTTPTransportError(err) {
					closeIdleConnections(c.client)
				}
				return err
			}
			return nil
		}); err != nil {
			return err
		}

		buf.Reset()
		pendingRaw = 0
		c.readiness.markPushReady()
		return nil
	}

	flushWithRetry := flush
	resetTimer(timer, flushInterval)

	enqueue := func(b []byte) error {
		for len(b) > 0 {
			chunk := b
			if len(chunk) > maxLineRawBytes {
				chunk = b[:maxLineRawBytes]
			}
			b = b[len(chunk):]

			encLen := base64.StdEncoding.EncodedLen(len(chunk))
			if pendingRaw+len(chunk) > maxBatchBytes || buf.Len()+encLen+1 > maxBatchBytes*2 {
				if err := flushWithRetry(); err != nil {
					return err
				}
			}

			tmp := encoded[:encLen]
			base64.StdEncoding.Encode(tmp, chunk)
			encoded[encLen] = '\n'
			_, _ = buf.Write(encoded[:encLen+1])
			pendingRaw += len(chunk)
		}
		return nil
	}

	for {
		select {
		case b := <-c.writeCh:
			if len(b) == 0 {
				continue
			}

			if err := enqueue(b); err != nil {
				fail(fmt.Errorf("poll push flush failed: %w", err))
				return
			}

			if pendingRaw >= maxBatchBytes {
				if err := flushWithRetry(); err != nil {
					fail(fmt.Errorf("poll push flush failed: %w", err))
					return
				}
				resetTimer(timer, flushInterval)
			}
		case <-timer.C:
			if err := flushWithRetry(); err != nil {
				fail(fmt.Errorf("poll push flush failed: %w", err))
				return
			}
			resetTimer(timer, flushInterval)
		case <-c.writeClosed:
			// Drain any already-accepted writes so CloseWrite does not lose data.
			for {
				select {
				case b := <-c.writeCh:
					if len(b) == 0 {
						continue
					}
					if err := enqueue(b); err != nil {
						fail(fmt.Errorf("poll push flush failed: %w", err))
						return
					}
				default:
					if err := flushWithRetry(); err != nil {
						fail(fmt.Errorf("poll push flush failed: %w", err))
						return
					}
					if err := sendSessionControl(c.client, c.finURL, c.headerHost, TunnelModePoll); err != nil {
						fail(fmt.Errorf("poll FIN failed: %w", err))
						return
					}
					return
				}
			}
		case <-c.closed:
			writeErr = c.closedErr()
			return
		}
	}
}
