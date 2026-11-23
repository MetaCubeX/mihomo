package gost

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	mihomoVMess "github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/smux"
)

const (
	relayVersion1 = 0x01

	relayCmdConnect = 0x01
	relayFlagUDP    = 0x80

	relayStatusOK                  = 0x00
	relayStatusBadRequest          = 0x01
	relayStatusUnauthorized        = 0x02
	relayStatusForbidden           = 0x03
	relayStatusTimeout             = 0x04
	relayStatusServiceUnavailable  = 0x05
	relayStatusHostUnreachable     = 0x06
	relayStatusNetworkUnreachable  = 0x07
	relayStatusInternalServerError = 0x08

	relayFeatureUserAuth = 0x01
	relayFeatureAddr     = 0x02
	relayFeatureNetwork  = 0x04

	relayAddrIPv4   = 0x01
	relayAddrDomain = 0x03
	relayAddrIPv6   = 0x04

	relayNetworkTCP = 0x0000
	relayNetworkUDP = 0x0001
)

// RelayOption is the common gost relay transport configuration that can wrap any TCP outbound dial.
type RelayOption struct {
	Server            string            `proxy:"server,omitempty"`
	Port              int               `proxy:"port,omitempty"`
	Forward           bool              `proxy:"forward,omitempty"`
	WS                bool              `proxy:"ws,omitempty"`
	WSPath            string            `proxy:"ws-path,omitempty"`
	WSHeaders         map[string]string `proxy:"ws-headers,omitempty"`
	TLS               bool              `proxy:"tls,omitempty"`
	Mux               bool              `proxy:"mux,omitempty"`
	SNI               string            `proxy:"sni,omitempty"`
	Username          string            `proxy:"username,omitempty"`
	Password          string            `proxy:"password,omitempty"`
	SkipCertVerify    bool              `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify    string            `proxy:"name-cert-verify,omitempty"`
	Fingerprint       string            `proxy:"fingerprint,omitempty"`
	Certificate       string            `proxy:"certificate,omitempty"`
	PrivateKey        string            `proxy:"private-key,omitempty"`
	ClientFingerprint string            `proxy:"client-fingerprint,omitempty"`
}

type relayDialer struct {
	base   C.Dialer
	option RelayOption
}

// NewRelayDialer wraps an existing dialer with gost relay connect support.
func NewRelayDialer(base C.Dialer, option *RelayOption) C.Dialer {
	if option == nil {
		return base
	}

	return &relayDialer{
		base:   base,
		option: *option,
	}
}

func (d *relayDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("gost relay only supports tcp dial, got %s", network)
	}

	conn, err := d.dialRelayServer(ctx, address)
	if err != nil {
		return nil, err
	}

	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()

	targetAddress := address
	if d.option.Forward {
		targetAddress = ""
	}
	if err := writeRelayRequest(conn, relayCmdConnect, targetAddress, relayNetworkTCP, d.option.Username, d.option.Password); err != nil {
		return nil, err
	}

	success = true
	return newRelayConn(conn), nil
}

func (d *relayDialer) ListenPacket(ctx context.Context, network, _ string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	if !strings.HasPrefix(network, "udp") {
		return nil, fmt.Errorf("gost relay only supports udp packet dial, got %s", network)
	}
	if !rAddrPort.IsValid() {
		return nil, fmt.Errorf("gost relay udp target address is required")
	}

	raddr := net.UDPAddrFromAddrPort(rAddrPort)
	conn, err := d.dialRelayServer(ctx, raddr.String())
	if err != nil {
		return nil, err
	}

	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()

	targetAddress := raddr.String()
	if d.option.Forward {
		targetAddress = ""
	}
	if err := writeRelayRequest(conn, relayCmdConnect|relayFlagUDP, targetAddress, relayNetworkUDP, d.option.Username, d.option.Password); err != nil {
		return nil, err
	}

	success = true
	return &relayPacketConn{
		conn:  conn,
		raddr: raddr,
	}, nil
}

func (d *relayDialer) dialRelayServer(ctx context.Context, fallbackAddress string) (net.Conn, error) {
	relayAddress := ""
	if d.option.Server != "" || d.option.Port > 0 {
		if d.option.Server == "" || d.option.Port <= 0 {
			return nil, fmt.Errorf("gost relay server and port are required")
		}
		relayAddress = net.JoinHostPort(d.option.Server, strconv.Itoa(d.option.Port))
	} else if d.option.Forward {
		relayAddress = fallbackAddress
	}
	if relayAddress == "" {
		return nil, fmt.Errorf("gost relay server and port are required")
	}

	conn, err := d.base.DialContext(ctx, "tcp", relayAddress)
	if err != nil {
		return nil, err
	}

	if d.option.WS {
		host, port, err := net.SplitHostPort(relayAddress)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("invalid gost relay websocket address %q: %w", relayAddress, err)
		}
		wsPath := d.option.WSPath
		if wsPath == "" {
			// Match the default path of GOST's ws/wss/mws/mwss listeners.
			wsPath = "/ws"
		}

		wsConn, err := NewGostWebsocket(ctx, conn, &Option{
			Host:              host,
			Port:              port,
			Path:              wsPath,
			Headers:           d.option.WSHeaders,
			TLS:               d.option.TLS,
			SNI:               d.option.SNI,
			SkipCertVerify:    d.option.SkipCertVerify,
			NameCertVerify:    d.option.NameCertVerify,
			Fingerprint:       d.option.Fingerprint,
			Certificate:       d.option.Certificate,
			PrivateKey:        d.option.PrivateKey,
			ClientFingerprint: d.option.ClientFingerprint,
			Mux:               d.option.Mux,
		})
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = wsConn
	} else {
		if d.option.TLS {
			tlsConn, err := mihomoVMess.StreamTLSConn(ctx, conn, &mihomoVMess.TLSConfig{
				Host:              d.serverName(relayAddress),
				SkipCertVerify:    d.option.SkipCertVerify,
				NameCertVerify:    d.option.NameCertVerify,
				FingerPrint:       d.option.Fingerprint,
				Certificate:       d.option.Certificate,
				PrivateKey:        d.option.PrivateKey,
				ClientFingerprint: d.option.ClientFingerprint,
			})
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			conn = tlsConn
		}

		if d.option.Mux {
			// Keep the default smux v1 and keepalive settings aligned with GOST.
			config := smux.DefaultConfig()

			session, err := smux.Client(conn, config)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}

			stream, err := session.OpenStream()
			if err != nil {
				_ = session.Close()
				return nil, err
			}

			conn = &muxConn{
				Conn:    stream,
				session: session,
			}
		}
	}

	return conn, nil
}

func (d *relayDialer) serverName(relayAddress string) string {
	if d.option.SNI != "" {
		return d.option.SNI
	}
	if d.option.Server != "" {
		return d.option.Server
	}
	host, _, err := net.SplitHostPort(relayAddress)
	if err != nil {
		return relayAddress
	}
	return host
}

func writeRelayRequest(w io.Writer, command byte, address string, network uint16, username, password string) error {
	features := make([][]byte, 0, 3)
	if username != "" || password != "" {
		if len(username) > 0xFF || len(password) > 0xFF {
			return fmt.Errorf("gost relay username or password too long")
		}
		authFeature, err := encodeRelayFeature(relayFeatureUserAuth, encodeRelayUserAuth(username, password))
		if err != nil {
			return err
		}
		features = append(features, authFeature)
	}

	if address != "" {
		addrPayload, err := encodeRelayAddr(address)
		if err != nil {
			return err
		}
		addrFeature, err := encodeRelayFeature(relayFeatureAddr, addrPayload)
		if err != nil {
			return err
		}
		features = append(features, addrFeature)
	}

	networkFeature, err := encodeRelayFeature(relayFeatureNetwork, []byte{byte(network >> 8), byte(network)})
	if err != nil {
		return err
	}
	features = append(features, networkFeature)

	payloadLen := 0
	for _, feature := range features {
		payloadLen += len(feature)
	}
	if payloadLen > 0xFFFF {
		return fmt.Errorf("gost relay feature list too large")
	}

	header := []byte{
		relayVersion1,
		command,
		byte(payloadLen >> 8),
		byte(payloadLen),
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	for _, feature := range features {
		if _, err := w.Write(feature); err != nil {
			return err
		}
	}
	return nil
}

// relayConn strips GOST's CONNECT response on the first read. With the
// default nodelay=false, GOST sends that response together with the first
// bytes received from the target, so waiting inside DialContext would stall.
type relayConn struct {
	net.Conn
	responseOnce sync.Once
	responseErr  error
}

func newRelayConn(conn net.Conn) net.Conn {
	wrapped := &relayConn{Conn: conn}
	if closeWriter, ok := conn.(interface{ CloseWrite() error }); ok {
		return &relayConnWithCloseWrite{
			relayConn:   wrapped,
			closeWriter: closeWriter,
		}
	}
	return wrapped
}

func (c *relayConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.responseOnce.Do(func() {
		c.responseErr = readRelayConnectResponse(c.Conn)
	})
	if c.responseErr != nil {
		return 0, c.responseErr
	}

	return c.Conn.Read(p)
}

// Keep TCP half-close available where the wrapped transport supports it.
type relayConnWithCloseWrite struct {
	*relayConn
	closeWriter interface{ CloseWrite() error }
}

func (c *relayConnWithCloseWrite) CloseWrite() error {
	return c.closeWriter.CloseWrite()
}

type relayPacketConn struct {
	conn         net.Conn
	raddr        net.Addr
	rmu          sync.Mutex
	wmu          sync.Mutex
	responseOnce sync.Once
	responseErr  error
}

func (c *relayPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	c.responseOnce.Do(func() {
		c.responseErr = readRelayConnectResponse(c.conn)
	})
	if c.responseErr != nil {
		return 0, nil, c.responseErr
	}

	var header [2]byte
	if _, err := io.ReadFull(c.conn, header[:]); err != nil {
		return 0, nil, err
	}

	packetLen := int(binary.BigEndian.Uint16(header[:]))
	if packetLen <= len(p) {
		n, err := io.ReadFull(c.conn, p[:packetLen])
		return n, c.raddr, err
	}

	buf := make([]byte, packetLen)
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		return 0, nil, err
	}
	return copy(p, buf), c.raddr, nil
}

func (c *relayPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > math.MaxUint16 {
		return 0, fmt.Errorf("gost relay udp packet too large: %d", len(p))
	}
	if addr != nil && c.raddr != nil && addr.String() != c.raddr.String() {
		return 0, fmt.Errorf("gost relay udp association is bound to %s, got %s", c.raddr, addr)
	}

	c.wmu.Lock()
	defer c.wmu.Unlock()

	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(p)))
	if _, err := c.conn.Write(header[:]); err != nil {
		return 0, err
	}
	if _, err := c.conn.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *relayPacketConn) Close() error {
	return c.conn.Close()
}

func (c *relayPacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *relayPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *relayPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *relayPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func readRelayConnectResponse(r io.Reader) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	if header[0] != relayVersion1 {
		return fmt.Errorf("gost relay bad version: %d", header[0])
	}
	if header[1] != relayStatusOK {
		return fmt.Errorf("gost relay connect failed with status 0x%02x (%s)", header[1], relayStatusText(header[1]))
	}

	featureLen := int(header[2])<<8 | int(header[3])
	if featureLen == 0 {
		return nil
	}

	_, err := io.CopyN(io.Discard, r, int64(featureLen))
	return err
}

func encodeRelayFeature(featureType byte, payload []byte) ([]byte, error) {
	if len(payload) > 0xFFFF {
		return nil, fmt.Errorf("gost relay feature payload too large")
	}

	out := make([]byte, 3+len(payload))
	out[0] = featureType
	out[1] = byte(len(payload) >> 8)
	out[2] = byte(len(payload))
	copy(out[3:], payload)
	return out, nil
}

func encodeRelayUserAuth(username, password string) []byte {
	out := make([]byte, 0, 2+len(username)+len(password))
	out = append(out, byte(len(username)))
	out = append(out, username...)
	out = append(out, byte(len(password)))
	out = append(out, password...)
	return out
}

func encodeRelayAddr(address string) ([]byte, error) {
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid relay target address %q: %w", address, err)
	}

	port, err := strconv.Atoi(portString)
	if err != nil || port < 0 || port > 0xFFFF {
		return nil, fmt.Errorf("invalid relay target port in %q", address)
	}

	out := make([]byte, 0, 1+1+len(host)+2)
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			out = append(out, relayAddrIPv4)
			out = append(out, ip4...)
		} else {
			out = append(out, relayAddrIPv6)
			out = append(out, ip.To16()...)
		}
	} else {
		if len(host) > 0xFF {
			return nil, fmt.Errorf("relay target host too long")
		}
		out = append(out, relayAddrDomain, byte(len(host)))
		out = append(out, host...)
	}

	out = append(out, byte(port>>8), byte(port))
	return out, nil
}

func relayStatusText(status byte) string {
	switch status {
	case relayStatusOK:
		return "ok"
	case relayStatusBadRequest:
		return "bad request"
	case relayStatusUnauthorized:
		return "unauthorized"
	case relayStatusForbidden:
		return "forbidden"
	case relayStatusTimeout:
		return "timeout"
	case relayStatusServiceUnavailable:
		return "service unavailable"
	case relayStatusHostUnreachable:
		return "host unreachable"
	case relayStatusNetworkUnreachable:
		return "network unreachable"
	case relayStatusInternalServerError:
		return "internal server error"
	default:
		return "unknown"
	}
}
