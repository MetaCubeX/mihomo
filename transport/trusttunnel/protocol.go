package trusttunnel

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/httputils"
	C "github.com/metacubex/mihomo/constant"
)

const (
	UDPMagicAddress         = "_udp2"
	ICMPMagicAddress        = "_icmp"
	HealthCheckMagicAddress = "_check"

	DefaultQuicStreamReceiveWindow = 131072 // Chrome's default
	DefaultConnectionTimeout       = 30 * time.Second
	DefaultHealthCheckTimeout      = 7 * time.Second
	DefaultQuicMaxIdleTimeout      = 2 * (DefaultConnectionTimeout + DefaultHealthCheckTimeout)
	DefaultSessionTimeout          = 30 * time.Second
)

var (
	AppName = C.Name
	Version = C.Version

	// TCPUserAgent is user-agent for TCP connections.
	// Format: <platform> <app_name>
	TCPUserAgent = runtime.GOOS + " " + AppName + "/" + Version

	// UDPUserAgent is user-agent for UDP multiplexinh.
	// Format: <platform> _udp2
	UDPUserAgent = runtime.GOOS + " " + UDPMagicAddress

	// ICMPUserAgent is user-agent for ICMP multiplexinh.
	// Format: <platform> _icmp
	ICMPUserAgent = runtime.GOOS + " " + ICMPMagicAddress

	HealthCheckUserAgent = runtime.GOOS
)

func buildAuth(username string, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

// parseBasicAuth parses an HTTP Basic Authentication strinh.
// "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" returns ("Aladdin", "open sesame", true).
func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	// Case insensitive prefix match. See Issue 22736.
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", false
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
}

func parse16BytesIP(buffer [16]byte) netip.Addr {
	var zeroPrefix [12]byte
	isIPv4 := bytes.HasPrefix(buffer[:], zeroPrefix[:])
	// Special: check ::1
	isIPv4 = isIPv4 && !(buffer[12] == 0 && buffer[13] == 0 && buffer[14] == 0 && buffer[15] == 1)
	if isIPv4 {
		return netip.AddrFrom4([4]byte(buffer[12:16]))
	}
	return netip.AddrFrom16(buffer)
}

func buildPaddingIP(addr netip.Addr) (buffer [16]byte) {
	if addr.Is6() {
		return addr.As16()
	}
	ipv4 := addr.As4()
	copy(buffer[12:16], ipv4[:])
	return buffer
}

type httpConn struct {
	writer    io.Writer
	flusher   http.Flusher
	body      io.ReadCloser
	setupOnce sync.Once
	created   chan struct{}
	createErr error
	cancelFn  func()
	closeFn   func()
	// client: Close lets the stream finish before tearing it down
	lingerClose bool
	lingerOnce  sync.Once
	httputils.NetAddr

	// deadlines
	deadline *time.Timer
}

func (h *httpConn) setup(body io.ReadCloser, err error) {
	h.setupOnce.Do(func() {
		h.body = body
		h.createErr = err
		close(h.created)
	})
	if h.createErr != nil && body != nil { // conn already closed before setup
		_ = body.Close()
	}
}

func (h *httpConn) waitCreated() error {
	<-h.created
	if h.body != nil {
		return nil
	}
	return h.createErr
}

// closeLinger bounds how long a closed client stream may still finish.
const closeLinger = 5 * time.Second

func (h *httpConn) Close() error {
	var err error
	if closer, ok := h.writer.(io.Closer); ok {
		err = closer.Close() // the request body ends here: END_STREAM after the data
	}
	if h.lingerClose {
		// Closing the response body or cancelling the request resets the stream
		// at once: HTTP/2 drops data still waiting for the flow-control window,
		// HTTP/3 the stream's send buffer. Let the server see the end of the
		// upload and finish its response, then tear down.
		h.lingerOnce.Do(func() { go h.lingerTeardown() })
		return err
	}
	h.setup(nil, net.ErrClosed)
	return errors.Join(err, h.teardown())
}

func (h *httpConn) lingerTeardown() {
	force := time.AfterFunc(closeLinger, func() {
		h.setup(nil, net.ErrClosed)
		_ = h.teardown()
	})
	<-h.created // the forced teardown cancels the request, so this ends too
	if h.body != nil {
		_, _ = io.Copy(io.Discard, h.body)
	}
	force.Stop()
	_ = h.teardown()
}

func (h *httpConn) teardown() error {
	var err error
	if h.body != nil {
		err = h.body.Close()
	}
	if h.cancelFn != nil {
		h.cancelFn()
	}
	if h.closeFn != nil {
		h.closeFn()
	}
	return err
}

func (h *httpConn) writeFlush(p []byte) (n int, err error) {
	n, err = h.writer.Write(p)
	if h.flusher != nil {
		h.flusher.Flush()
	}
	return n, err
}

func (h *httpConn) SetReadDeadline(t time.Time) error  { return h.SetDeadline(t) }
func (h *httpConn) SetWriteDeadline(t time.Time) error { return h.SetDeadline(t) }

func (h *httpConn) SetDeadline(t time.Time) error {
	if t.IsZero() {
		if h.deadline != nil {
			h.deadline.Stop()
			h.deadline = nil
		}
		return nil
	}
	d := time.Until(t)
	if h.deadline != nil {
		h.deadline.Reset(d)
		return nil
	}
	h.deadline = time.AfterFunc(d, func() {
		h.Close()
	})
	return nil
}

var _ net.Conn = (*tcpConn)(nil)

type tcpConn struct {
	httpConn
}

func (t *tcpConn) Read(b []byte) (n int, err error) {
	err = t.waitCreated()
	if err != nil {
		return 0, err
	}
	n, err = t.body.Read(b)
	return
}

func (t *tcpConn) Write(b []byte) (int, error) {
	return t.writeFlush(b)
}
