package masque

// copy and modify from: https://github.com/Diniboy1123/connect-ip-go/blob/8d7bb0a858a2674046a7cb5538749e4c826c3538/client_h2.go

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go/quicvarint"
	"github.com/yosida95/uritemplate/v3"
)

const h2DatagramCapsuleType uint64 = 0

const (
	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
)

func ConnectTunnelH2(ctx context.Context, h2Transport *http.Http2Transport, connectUri string) (*http.Http2ClientConn, IpConn, error) {
	additionalHeaders := http.Header{
		"User-Agent": []string{""},
	}
	template := uritemplate.MustNew(connectUri)

	h2Headers := additionalHeaders.Clone()
	h2Headers.Set("cf-connect-proto", "cf-connect-ip")
	// TODO: support PQC
	h2Headers.Set("pq-enabled", "false")

	conn, err := h2Transport.DialTLSContext(ctx, "tcp", ":0", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to dial: %w", err)
	}

	cc, err := h2Transport.NewClientConn(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to create client connection: %w", err)
	}

	if !cc.ReserveNewRequest() {
		_ = cc.Close()
		return nil, nil, fmt.Errorf("connect-ip: failed to reserve client connection: %w", err)
	}

	ipConn, rsp, err := dialH2(ctx, cc, template, h2Headers)
	if err != nil {
		_ = cc.Close()
		if strings.Contains(err.Error(), "tls: access denied") {
			return nil, nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
		}
		return nil, nil, fmt.Errorf("failed to dial connect-ip over HTTP/2: %w", err)
	}

	if rsp.StatusCode != http.StatusOK {
		_ = ipConn.Close()
		_ = cc.Close()
		return nil, nil, fmt.Errorf("failed to dial connect-ip: %v", rsp.Status)
	}

	return cc, ipConn, nil
}

// dialH2 dials a proxied connection over HTTP/2 CONNECT-IP.
//
// This transport carries proxied packets inside HTTP capsule DATAGRAM frames.
func dialH2(ctx context.Context, rt http.RoundTripper, template *uritemplate.Template, additionalHeaders http.Header) (*h2IpConn, *http.Response, error) {
	if len(template.Varnames()) > 0 {
		return nil, nil, errors.New("connect-ip: IP flow forwarding not supported")
	}

	u, err := url.Parse(template.Raw())
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to parse URI: %w", err)
	}

	reqCtx, cancel := context.WithCancel(context.Background()) // reqCtx must disconnect from ctx, otherwise ctx would close the entire HTTP/2 connection.

	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodConnect, u.String(), pr)
	if err != nil {
		cancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, nil, fmt.Errorf("connect-ip: failed to create request: %w", err)
	}
	req.Host = authorityFromURL(u)
	req.ContentLength = -1
	req.Header = make(http.Header)
	for k, v := range additionalHeaders {
		req.Header[k] = v
	}

	stop := contextutils.AfterFunc(ctx, cancel) // temporarily connect ctx with reqCtx when client.Do
	rsp, err := rt.RoundTrip(req)
	stop() // disconnect ctx with reqCtx after client.Do
	if err != nil {
		cancel()
		_ = pr.Close()
		_ = pw.Close()
		return nil, nil, fmt.Errorf("connect-ip: failed to send request: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		cancel()
		_ = pr.Close()
		_ = pw.Close()
		_ = rsp.Body.Close()
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %d", rsp.StatusCode)
	}

	stream := &h2DatagramStream{
		requestBody:  pw,
		responseBody: rsp.Body,
		cancel:       cancel,
	}
	return &h2IpConn{
		str:       stream,
		closeChan: make(chan struct{}),
	}, rsp, nil
}

func authorityFromURL(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	host := u.Hostname()
	if host == "" {
		return u.Host
	}
	return host + ":443"
}

type h2IpConn struct {
	str *h2DatagramStream

	mu sync.Mutex

	closeChan chan struct{}
	closeErr  error
}

func (c *h2IpConn) ReadPacket() (b []byte, err error) {
start:
	data, err := c.str.ReceiveDatagram(context.Background())
	if err != nil {
		defer func() {
			// There are no errors that can be recovered in h2 mode,
			// so calling Close allows the outer read loop to exit in the next iteration by returning net.ErrClosed.
			_ = c.Close()
		}()
		select {
		case <-c.closeChan:
			return nil, c.closeErr
		default:
			return nil, err
		}
	}
	if err := c.handleIncomingProxiedPacket(data); err != nil {
		log.Debugln("dropping proxied packet: %s", err)
		goto start
	}
	return data, nil
}

func (c *h2IpConn) handleIncomingProxiedPacket(data []byte) error {
	if len(data) == 0 {
		return errors.New("connect-ip: empty packet")
	}
	switch v := ipVersion(data); v {
	default:
		return fmt.Errorf("connect-ip: unknown IP versions: %d", v)
	case 4:
		if len(data) < ipv4HeaderLen {
			return fmt.Errorf("connect-ip: malformed datagram: too short")
		}
	case 6:
		if len(data) < ipv6HeaderLen {
			return fmt.Errorf("connect-ip: malformed datagram: too short")
		}
	}
	return nil
}

// WritePacket writes an IP packet to the stream.
// If sending the packet fails, it might return an ICMP packet.
// It is the caller's responsibility to send the ICMP packet to the sender.
func (c *h2IpConn) WritePacket(b []byte) (icmp []byte, err error) {
	data, err := c.composeDatagram(b)
	if err != nil {
		log.Debugln("dropping proxied packet (%d bytes) that can't be proxied: %s", len(b), err)
		return nil, nil
	}
	if err := c.str.SendDatagram(data); err != nil {
		select {
		case <-c.closeChan:
			return nil, c.closeErr
		default:
			return nil, err
		}
	}
	return nil, nil
}

func (c *h2IpConn) composeDatagram(b []byte) ([]byte, error) {
	// TODO: implement src, dst and ipproto checks
	if len(b) == 0 {
		return nil, nil
	}
	switch v := ipVersion(b); v {
	default:
		return nil, fmt.Errorf("connect-ip: unknown IP versions: %d", v)
	case 4:
		if len(b) < ipv4HeaderLen {
			return nil, fmt.Errorf("connect-ip: IPv4 packet too short")
		}
		ttl := b[8]
		if ttl <= 1 {
			return nil, fmt.Errorf("connect-ip: datagram TTL too small: %d", ttl)
		}
		b[8]-- // decrement TTL
		// recalculate the checksum
		binary.BigEndian.PutUint16(b[10:12], calculateIPv4Checksum(([ipv4HeaderLen]byte)(b[:ipv4HeaderLen])))
	case 6:
		if len(b) < ipv6HeaderLen {
			return nil, fmt.Errorf("connect-ip: IPv6 packet too short")
		}
		hopLimit := b[7]
		if hopLimit <= 1 {
			return nil, fmt.Errorf("connect-ip: datagram Hop Limit too small: %d", hopLimit)
		}
		b[7]-- // Decrement Hop Limit
	}
	return b, nil
}

func (c *h2IpConn) Close() error {
	c.mu.Lock()
	if c.closeErr == nil {
		c.closeErr = net.ErrClosed
		close(c.closeChan)
	}
	c.mu.Unlock()
	err := c.str.Close()
	return err
}

func ipVersion(b []byte) uint8 { return b[0] >> 4 }

func calculateIPv4Checksum(header [ipv4HeaderLen]byte) uint16 {
	// add every 16-bit word in the header, skipping the checksum field (bytes 10 and 11)
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		if i == 10 {
			continue // skip checksum field
		}
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

type h2DatagramStream struct {
	requestBody  *io.PipeWriter
	responseBody io.ReadCloser
	cancel       context.CancelFunc

	readMu  sync.Mutex
	writeMu sync.Mutex
}

func (s *h2DatagramStream) ReceiveDatagram(_ context.Context) ([]byte, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	reader := quicvarint.NewReader(s.responseBody)
	for {
		capsuleType, err := quicvarint.Read(reader)
		if err != nil {
			return nil, err
		}
		payloadLen, err := quicvarint.Read(reader)
		if err != nil {
			return nil, err
		}
		payload := make([]byte, payloadLen)
		_, err = io.ReadFull(reader, payload)
		if err != nil {
			return nil, err
		}
		if capsuleType != h2DatagramCapsuleType {
			continue
		}
		return payload, nil
	}
}

func (s *h2DatagramStream) SendDatagram(data []byte) error {
	frame := make([]byte, 0, quicvarint.Len(h2DatagramCapsuleType)+quicvarint.Len(uint64(len(data)))+len(data))
	frame = quicvarint.Append(frame, h2DatagramCapsuleType)
	frame = quicvarint.Append(frame, uint64(len(data)))
	frame = append(frame, data...)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.requestBody.Write(frame)
	if err != nil {
		return fmt.Errorf("connect-ip: failed to send datagram capsule: %w", err)
	}
	return nil
}

func (s *h2DatagramStream) Close() error {
	_ = s.requestBody.Close()
	err := s.responseBody.Close()
	s.cancel()
	return err
}
