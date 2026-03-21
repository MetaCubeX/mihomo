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
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/gun"
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
	created   chan struct{}
	createErr error
	gun.NetAddr

	// deadlines
	deadline *time.Timer
}

func (h *httpConn) setUp(body io.ReadCloser, err error) {
	h.body = body
	h.createErr = err
	close(h.created)
}

func (h *httpConn) waitCreated() error {
	if h.body != nil || h.createErr != nil {
		return h.createErr
	}
	<-h.created
	return h.createErr
}

func (h *httpConn) Close() error {
	var errorArr []error
	if closer, ok := h.writer.(io.Closer); ok {
		errorArr = append(errorArr, closer.Close())
	}
	if h.body != nil {
		errorArr = append(errorArr, h.body.Close())
	}
	return errors.Join(errorArr...)
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
