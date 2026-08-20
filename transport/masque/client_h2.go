package masque

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	connectip "github.com/metacubex/connect-ip-go"
	"github.com/metacubex/mihomo/common/contextutils"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/quic-go/quicvarint"
)

const (
	h2DatagramCapsuleType http3.CapsuleType = 0
	maxH2CapsuleSize                        = 4 << 20
)

// ConnectTunnelH2 establishes a standards-compliant CONNECT-IP tunnel over
// HTTP/2. HTTP Datagrams are carried as DATAGRAM capsules, as required by RFC
// 9297 when QUIC datagrams are unavailable.
func ConnectTunnelH2(ctx context.Context, transport *http.Transport, connectURI string, additionalHeaders http.Header) (*http.ClientConn, *connectip.Conn, error) {
	u, err := ParseTunnelURL(connectURI)
	if err != nil {
		return nil, nil, err
	}
	cc, err := transport.NewClientConn(ctx, "https", u.Host)
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: create HTTP/2 client connection: %w", err)
	}
	if err = cc.Reserve(); err != nil {
		_ = cc.Close()
		return nil, nil, fmt.Errorf("connect-ip: reserve HTTP/2 client connection: %w", err)
	}
	ipConn, rsp, err := dialHTTP2(ctx, cc, u.String(), additionalHeaders)
	if err != nil {
		_ = cc.Close()
		return nil, nil, err
	}
	if err := validateCapsuleProtocol(rsp.Header); err != nil {
		_ = ipConn.Close()
		_ = cc.Close()
		return nil, nil, err
	}
	return cc, ipConn, nil
}

func dialHTTP2(ctx context.Context, rt http.RoundTripper, connectURI string, additionalHeaders http.Header) (*connectip.Conn, *http.Response, error) {
	reqCtx, cancel := context.WithCancel(context.Background())
	requestReader, requestWriter := io.Pipe()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodConnect, connectURI, requestReader)
	if err != nil {
		cancel()
		_ = requestReader.Close()
		_ = requestWriter.Close()
		return nil, nil, fmt.Errorf("connect-ip: create HTTP/2 request: %w", err)
	}
	req.Host = req.URL.Host
	req.ContentLength = -1
	req.Header, err = requestHeaders(additionalHeaders)
	if err != nil {
		cancel()
		_ = requestReader.Close()
		_ = requestWriter.Close()
		return nil, nil, err
	}
	// The metacubex HTTP backport maps this sentinel header to the HTTP/2
	// :protocol pseudo-header and waits for SETTINGS_ENABLE_CONNECT_PROTOCOL.
	req.Header.Set(":protocol", RequestProtocol)

	stop := contextutils.AfterFunc(ctx, cancel)
	rsp, err := rt.RoundTrip(req)
	stop()
	if err != nil {
		cancel()
		_ = requestReader.Close()
		_ = requestWriter.Close()
		return nil, nil, fmt.Errorf("connect-ip: send HTTP/2 request: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		cancel()
		_ = requestReader.Close()
		_ = requestWriter.Close()
		_ = rsp.Body.Close()
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %s", rsp.Status)
	}

	stream := newH2CapsuleStream(requestWriter, rsp.Body, cancel)
	return connectip.NewProxiedConn(stream), rsp, nil
}

// h2CapsuleStream adapts the single bidirectional HTTP/2 DATA stream to the
// split stream/datagram interface used by connect-ip-go. One read loop
// demultiplexes DATAGRAM capsules from CONNECT-IP control capsules.
type h2CapsuleStream struct {
	requestBody  *io.PipeWriter
	responseBody io.ReadCloser
	cancel       context.CancelFunc

	controlReader *io.PipeReader
	controlWriter *io.PipeWriter
	datagrams     chan []byte
	done          chan struct{}

	writeMu   sync.Mutex
	closeOnce sync.Once
	errMu     sync.Mutex
	closeErr  error
}

func newH2CapsuleStream(requestBody *io.PipeWriter, responseBody io.ReadCloser, cancel context.CancelFunc) *h2CapsuleStream {
	controlReader, controlWriter := io.Pipe()
	s := &h2CapsuleStream{
		requestBody:   requestBody,
		responseBody:  responseBody,
		cancel:        cancel,
		controlReader: controlReader,
		controlWriter: controlWriter,
		datagrams:     make(chan []byte, 16),
		done:          make(chan struct{}),
	}
	go s.readCapsules()
	return s
}

func (s *h2CapsuleStream) readCapsules() {
	parser := http3.NewCapsuleParser(s.responseBody)
	for {
		capsuleType, reader, err := parser.Next()
		if err != nil {
			s.closeWithError(err)
			return
		}
		payload, err := io.ReadAll(io.LimitReader(reader, maxH2CapsuleSize+1))
		if err != nil {
			s.closeWithError(err)
			return
		}
		if len(payload) > maxH2CapsuleSize {
			s.closeWithError(errors.New("connect-ip: HTTP/2 capsule exceeds size limit"))
			return
		}
		if capsuleType == h2DatagramCapsuleType {
			select {
			case s.datagrams <- payload:
			case <-s.done:
				return
			}
			continue
		}
		frame := appendCapsule(nil, capsuleType, payload)
		if _, err := s.controlWriter.Write(frame); err != nil {
			s.closeWithError(err)
			return
		}
	}
}

func (s *h2CapsuleStream) Read(p []byte) (int, error) {
	return s.controlReader.Read(p)
}

func (s *h2CapsuleStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.requestBody.Write(p)
}

func (s *h2CapsuleStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	// Prefer already-demultiplexed datagrams over the terminal stream error.
	// Both cases can become ready when an HTTP/2 response ends immediately
	// after its final capsule.
	select {
	case data := <-s.datagrams:
		return data, nil
	default:
	}
	select {
	case data := <-s.datagrams:
		return data, nil
	case <-s.done:
		select {
		case data := <-s.datagrams:
			return data, nil
		default:
			return nil, s.err()
		}
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

func (s *h2CapsuleStream) SendDatagram(data []byte) error {
	frame := appendCapsule(nil, h2DatagramCapsuleType, data)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.requestBody.Write(frame); err != nil {
		return fmt.Errorf("connect-ip: send HTTP/2 DATAGRAM capsule: %w", err)
	}
	return nil
}

func appendCapsule(dst []byte, capsuleType http3.CapsuleType, payload []byte) []byte {
	dst = quicvarint.Append(dst, uint64(capsuleType))
	dst = quicvarint.Append(dst, uint64(len(payload)))
	return append(dst, payload...)
}

func (s *h2CapsuleStream) CancelRead(quic.StreamErrorCode) {
	s.closeWithError(net.ErrClosed)
}

func (s *h2CapsuleStream) Close() error {
	s.closeWithError(net.ErrClosed)
	return nil
}

func (s *h2CapsuleStream) closeWithError(err error) {
	s.closeOnce.Do(func() {
		if err == nil {
			err = net.ErrClosed
		}
		s.errMu.Lock()
		s.closeErr = err
		s.errMu.Unlock()
		close(s.done)
		s.cancel()
		_ = s.requestBody.CloseWithError(err)
		_ = s.responseBody.Close()
		_ = s.controlWriter.CloseWithError(err)
		_ = s.controlReader.CloseWithError(err)
	})
}

func (s *h2CapsuleStream) err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	if s.closeErr == nil {
		return errors.New("connect-ip: HTTP/2 capsule stream closed")
	}
	return s.closeErr
}
