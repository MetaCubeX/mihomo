package warp

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
)

const (
	h2DatagramCapsuleType uint64 = 0
	ipv4HeaderLen                = 20
	ipv6HeaderLen                = 40
	maxH2CapsulePayload          = 4 << 20
)

// ConnectTunnelH2 establishes Cloudflare WARP's private HTTP/2 fallback. It
// uses a classic CONNECT request with cf-connect-proto and carries raw IP
// packets (without a Context ID) in DATAGRAM capsules.
func ConnectTunnelH2(ctx context.Context, transport *http.Transport, connectURI string) (*http.ClientConn, IpConn, error) {
	cc, err := transport.NewClientConn(ctx, "https", ":0")
	if err != nil {
		return nil, nil, fmt.Errorf("warp: create HTTP/2 client connection: %w", err)
	}
	if err = cc.Reserve(); err != nil {
		_ = cc.Close()
		return nil, nil, fmt.Errorf("warp: reserve HTTP/2 client connection: %w", err)
	}
	ipConn, _, err := dialHTTP2(ctx, cc, connectURI)
	if err != nil {
		_ = cc.Close()
		if strings.Contains(err.Error(), "tls: access denied") {
			return nil, nil, errors.New("warp: MASQUE authentication failed")
		}
		return nil, nil, fmt.Errorf("warp: dial MASQUE over HTTP/2: %w", err)
	}
	return cc, ipConn, nil
}

func dialHTTP2(ctx context.Context, rt http.RoundTripper, connectURI string) (*h2IPConn, *http.Response, error) {
	u, err := url.Parse(connectURI)
	if err != nil {
		return nil, nil, fmt.Errorf("warp: parse MASQUE URI: %w", err)
	}
	reqCtx, cancel := context.WithCancel(context.Background())
	requestReader, requestWriter := io.Pipe()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodConnect, u.String(), requestReader)
	if err != nil {
		cancel()
		_ = requestReader.Close()
		_ = requestWriter.Close()
		return nil, nil, err
	}
	req.Host = authorityFromURL(u)
	req.ContentLength = -1
	req.Header.Set("User-Agent", "")
	req.Header.Set("cf-connect-proto", requestProtocol)
	req.Header.Set("pq-enabled", "false")

	stop := contextutils.AfterFunc(ctx, cancel)
	rsp, err := rt.RoundTrip(req)
	stop()
	if err != nil {
		cancel()
		_ = requestReader.Close()
		_ = requestWriter.Close()
		return nil, nil, err
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		cancel()
		_ = requestReader.Close()
		_ = requestWriter.Close()
		_ = rsp.Body.Close()
		return nil, rsp, fmt.Errorf("server responded with %s", rsp.Status)
	}
	return &h2IPConn{
		stream: &h2DatagramStream{
			requestBody:  requestWriter,
			responseBody: rsp.Body,
			cancel:       cancel,
		},
		closed: make(chan struct{}),
	}, rsp, nil
}

func authorityFromURL(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	if u.Hostname() == "" {
		return u.Host
	}
	return net.JoinHostPort(u.Hostname(), "443")
}

type h2IPConn struct {
	stream *h2DatagramStream

	mu       sync.Mutex
	closed   chan struct{}
	closeErr error
}

func (c *h2IPConn) ReadPacket() ([]byte, error) {
	for {
		data, err := c.stream.ReceiveDatagram()
		if err != nil {
			err = c.setCloseError(err)
			_ = c.stream.Close()
			return nil, err
		}
		if err := validateIPPacket(data); err != nil {
			log.Debugln("[Warp] dropping malformed proxied packet: %v", err)
			continue
		}
		return data, nil
	}
}

func (c *h2IPConn) WritePacket(packet []byte) ([]byte, error) {
	if err := decrementHopLimit(packet); err != nil {
		log.Debugln("[Warp] dropping proxied packet: %v", err)
		return nil, nil
	}
	if err := c.stream.SendDatagram(packet); err != nil {
		select {
		case <-c.closed:
			return nil, c.closeErr
		default:
			return nil, err
		}
	}
	return nil, nil
}

func (c *h2IPConn) Close() error {
	c.setCloseError(net.ErrClosed)
	return c.stream.Close()
}

func (c *h2IPConn) setCloseError(err error) error {
	c.mu.Lock()
	if c.closeErr == nil {
		c.closeErr = err
		close(c.closed)
	}
	err = c.closeErr
	c.mu.Unlock()
	return err
}

func validateIPPacket(packet []byte) error {
	if len(packet) == 0 {
		return errors.New("empty packet")
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < ipv4HeaderLen {
			return errors.New("IPv4 packet too short")
		}
		headerLength := int(packet[0]&0x0f) * 4
		if headerLength < ipv4HeaderLen {
			return fmt.Errorf("invalid IPv4 header length %d", headerLength)
		}
		if headerLength > len(packet) {
			return fmt.Errorf("IPv4 header length %d exceeds packet length %d", headerLength, len(packet))
		}
	case 6:
		if len(packet) < ipv6HeaderLen {
			return errors.New("IPv6 packet too short")
		}
	default:
		return fmt.Errorf("unknown IP version %d", packet[0]>>4)
	}
	return nil
}

func decrementHopLimit(packet []byte) error {
	if err := validateIPPacket(packet); err != nil {
		return err
	}
	switch packet[0] >> 4 {
	case 4:
		if packet[8] <= 1 {
			return fmt.Errorf("IPv4 TTL too small: %d", packet[8])
		}
		packet[8]--
		headerLength := int(packet[0]&0x0f) * 4
		binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:headerLength]))
	case 6:
		if packet[7] <= 1 {
			return fmt.Errorf("IPv6 hop limit too small: %d", packet[7])
		}
		packet[7]--
	}
	return nil
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for index := 0; index < len(header); index += 2 {
		if index == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(header[index : index+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

type h2DatagramStream struct {
	requestBody  *io.PipeWriter
	responseBody io.ReadCloser
	cancel       context.CancelFunc

	readMu    sync.Mutex
	writeMu   sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

func (s *h2DatagramStream) ReceiveDatagram() ([]byte, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	reader := quicvarint.NewReader(s.responseBody)
	for {
		capsuleType, err := quicvarint.Read(reader)
		if err != nil {
			return nil, err
		}
		payloadLength, err := quicvarint.Read(reader)
		if err != nil {
			return nil, err
		}
		if payloadLength > maxH2CapsulePayload {
			return nil, errors.New("warp: HTTP/2 capsule exceeds size limit")
		}
		payload := make([]byte, payloadLength)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, err
		}
		if capsuleType == h2DatagramCapsuleType {
			return payload, nil
		}
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
	return err
}

func (s *h2DatagramStream) Close() error {
	s.closeOnce.Do(func() {
		if s.requestBody != nil {
			_ = s.requestBody.Close()
		}
		if s.responseBody != nil {
			s.closeErr = s.responseBody.Close()
		}
		if s.cancel != nil {
			s.cancel()
		}
	})
	return s.closeErr
}
