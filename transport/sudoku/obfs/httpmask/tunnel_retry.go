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
	"errors"
	"github.com/metacubex/http"
	"io"
	"net"
	"net/url"
	"strings"
	"syscall"
	"time"
)

type httpStatusError struct {
	code   int
	status string
}

func (e *httpStatusError) Error() string {
	if e == nil || e.status == "" {
		return "bad status"
	}
	return "bad status: " + e.status
}

func isRetryableStatusCode(code int) bool {
	return code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || code >= 500
}

func statusError(resp *http.Response) error {
	if resp == nil {
		return &httpStatusError{}
	}
	return &httpStatusError{code: resp.StatusCode, status: resp.Status}
}

type idleConnCloser interface{ CloseIdleConnections() }

func closeIdleConnections(client *http.Client) {
	if client == nil || client.Transport == nil {
		return
	}
	if closer, ok := client.Transport.(idleConnCloser); ok {
		closer.CloseIdleConnections()
	}
}

func isDialError(err error) bool {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return isDialError(urlErr.Err)
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op == "dial" || opErr.Op == "connect" {
			return true
		}
	}
	return false
}

func isRetryableHTTPTransportError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) {
		return isRetryableStatusCode(statusErr.code)
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return isRetryableHTTPTransportError(urlErr.Err)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) {
		return true
	}
	if strings.Contains(strings.ToLower(err.Error()), "server closed idle connection") {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary())
}

func resetTimer(t *time.Timer, d time.Duration) {
	if t == nil {
		return
	}
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

func retryPersistent(closed <-chan struct{}, closedErr func() error, minBackoff, maxBackoff time.Duration, fn func() error) error {
	if minBackoff < 0 {
		minBackoff = 0
	}
	if maxBackoff < minBackoff {
		maxBackoff = minBackoff
	}
	backoff := minBackoff
	for {
		if err := fn(); err == nil {
			return nil
		} else if isDialError(err) || isRetryableHTTPTransportError(err) {
			select {
			case <-time.After(backoff):
			case <-closed:
				if closedErr != nil {
					return closedErr()
				}
				return io.ErrClosedPipe
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		} else {
			return err
		}
	}
}

func waitRetry(closed <-chan struct{}, closedErr func() error, backoff time.Duration) error {
	if backoff < 0 {
		backoff = 0
	}
	timer := time.NewTimer(backoff)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-closed:
		if closedErr != nil {
			return closedErr()
		}
		return io.ErrClosedPipe
	}
}

func nextBackoff(current, min, max time.Duration) time.Duration {
	if current < min {
		current = min
	}
	if current >= max/2 {
		return max
	}
	return current * 2
}
