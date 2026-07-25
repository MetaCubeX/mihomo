//go:build darwin

package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	D "github.com/miekg/dns"
)

// This is the versioned IPC protocol used by Apple's public dns_sd.h client
// library. Keeping the small A/AAAA subset here lets release builds remain
// CGO-free while still using the shared mDNSResponder service as Apple
// recommends. Protocol definitions:
// https://github.com/apple-oss-distributions/mDNSResponder/blob/main/mDNSShared/dnssd_ipc.h
const (
	mdnsResponderDefaultSocket  = "/var/run/mDNSResponder"
	mdnsResponderIPCVersion     = 1
	mdnsResponderHeaderSize     = 28
	mdnsResponderReplyHeader    = 12
	mdnsResponderAddrInfoOp     = 15
	mdnsResponderAddrInfoReply  = 72
	mdnsResponderForceMulticast = 0x400
	mdnsResponderFlagAdd        = 0x2
	mdnsResponderProtocolIPv4   = 0x1
	mdnsResponderProtocolIPv6   = 0x2
	mdnsResponderTimeoutError   = -65568
)

func (c *mdnsClient) exchangeMDNSPlatform(ctx context.Context, request *D.Msg) (*D.Msg, bool, error) {
	question := request.Question[0]
	var protocol uint32
	switch question.Qtype {
	case D.TypeA:
		protocol = mdnsResponderProtocolIPv4
	case D.TypeAAAA:
		protocol = mdnsResponderProtocolIPv6
	default:
		return nil, false, nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	socketPath := os.Getenv("DNSSD_UDS_PATH")
	if socketPath == "" {
		socketPath = mdnsResponderDefaultSocket
	}
	conn, err := (&net.Dialer{}).DialContext(queryCtx, "unix", socketPath)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, true, ctxErr
		}
		return nil, false, nil // Let the portable multicast transport try.
	}
	if !c.registerSocket(conn) {
		_ = conn.Close()
		return nil, true, errMDNSClientClosed
	}
	defer func() {
		_ = conn.Close()
		c.unregisterSocket(conn)
	}()

	stopCancellation := make(chan struct{})
	defer close(stopCancellation)
	go func() {
		select {
		case <-queryCtx.Done():
			_ = conn.Close()
		case <-stopCancellation:
		}
	}()

	if deadline, ok := queryCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err = writeMDNSResponderRequest(conn, question.Name, protocol); err != nil {
		return nil, true, c.mdnsResponderError(queryCtx, err)
	}

	var initialError [4]byte
	if _, err = io.ReadFull(conn, initialError[:]); err != nil {
		return nil, true, c.mdnsResponderError(queryCtx, err)
	}
	if code := int32(binary.BigEndian.Uint32(initialError[:])); code != 0 {
		return nil, true, fmt.Errorf("mDNSResponder rejected query: error %d", code)
	}

	var responses []*D.Msg
	for {
		message, flags, code, err := readMDNSResponderReply(conn, request)
		if err != nil {
			if len(responses) > 0 && isTimeoutError(err) {
				return mergeMDNSResponses(request, responses), true, nil
			}
			return nil, true, c.mdnsResponderError(queryCtx, err)
		}
		if code != 0 {
			if code == mdnsResponderTimeoutError {
				if len(responses) > 0 {
					return mergeMDNSResponses(request, responses), true, nil
				}
				return nil, true, fmt.Errorf("%w: mDNSResponder error %d", errMDNSTimeout, code)
			}
			return nil, true, fmt.Errorf("mDNSResponder query failed: error %d", code)
		}
		if flags&mdnsResponderFlagAdd != 0 && message != nil {
			responses = append(responses, message)
			_ = conn.SetReadDeadline(time.Now().Add(c.settle))
		}
	}
}

func (c *mdnsClient) mdnsResponderError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			return fmt.Errorf("%w: %w", errMDNSTimeout, ctxErr)
		}
		return ctxErr
	}
	if c.isClosed() {
		return errMDNSClientClosed
	}
	if isTimeoutError(err) {
		return fmt.Errorf("%w: %w", errMDNSTimeout, err)
	}
	return fmt.Errorf("mDNSResponder IPC: %w", err)
}

func writeMDNSResponderRequest(writer io.Writer, hostname string, protocol uint32) error {
	hostname = D.Fqdn(hostname)
	dataLength := 3*4 + len(hostname) + 1
	message := make([]byte, mdnsResponderHeaderSize+dataLength)
	binary.BigEndian.PutUint32(message[0:4], mdnsResponderIPCVersion)
	binary.BigEndian.PutUint32(message[4:8], uint32(dataLength))
	binary.BigEndian.PutUint32(message[12:16], mdnsResponderAddrInfoOp)
	binary.BigEndian.PutUint32(message[28:32], mdnsResponderForceMulticast)
	binary.BigEndian.PutUint32(message[32:36], 0) // All eligible interfaces.
	binary.BigEndian.PutUint32(message[36:40], protocol)
	copy(message[40:], hostname)
	return writeAll(writer, message)
}

func readMDNSResponderReply(reader io.Reader, request *D.Msg) (*D.Msg, uint32, int32, error) {
	header := make([]byte, mdnsResponderHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, 0, 0, err
	}
	if version := binary.BigEndian.Uint32(header[0:4]); version != mdnsResponderIPCVersion {
		return nil, 0, 0, fmt.Errorf("unsupported mDNSResponder IPC version %d", version)
	}
	dataLength := binary.BigEndian.Uint32(header[4:8])
	if dataLength < mdnsResponderReplyHeader || dataLength > mdnsMaxDatagramSize {
		return nil, 0, 0, fmt.Errorf("invalid mDNSResponder reply length %d", dataLength)
	}
	if operation := binary.BigEndian.Uint32(header[12:16]); operation != mdnsResponderAddrInfoReply {
		return nil, 0, 0, fmt.Errorf("unexpected mDNSResponder reply operation %d", operation)
	}

	body := make([]byte, dataLength)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, 0, 0, err
	}
	flags := binary.BigEndian.Uint32(body[0:4])
	code := int32(binary.BigEndian.Uint32(body[8:12]))
	if code != 0 {
		return nil, flags, code, nil
	}

	nameEnd := bytes.IndexByte(body[mdnsResponderReplyHeader:], 0)
	if nameEnd < 0 {
		return nil, 0, 0, errors.New("unterminated hostname in mDNSResponder reply")
	}
	nameEnd += mdnsResponderReplyHeader
	name := string(body[mdnsResponderReplyHeader:nameEnd])
	offset := nameEnd + 1
	if len(body)-offset < 3*2+4 {
		return nil, 0, 0, errors.New("truncated mDNSResponder reply")
	}
	rrType := binary.BigEndian.Uint16(body[offset : offset+2])
	rrClass := binary.BigEndian.Uint16(body[offset+2 : offset+4])
	rdLength := int(binary.BigEndian.Uint16(body[offset+4 : offset+6]))
	offset += 6
	if len(body)-offset < rdLength+4 {
		return nil, 0, 0, errors.New("invalid rdata length in mDNSResponder reply")
	}
	rdata := body[offset : offset+rdLength]
	ttl := binary.BigEndian.Uint32(body[offset+rdLength : offset+rdLength+4])

	headerRR := D.RR_Header{Name: D.Fqdn(name), Rrtype: rrType, Class: rrClass, Ttl: ttl}
	var answer D.RR
	switch {
	case rrType == D.TypeA && rdLength == net.IPv4len:
		answer = &D.A{Hdr: headerRR, A: net.IP(append([]byte(nil), rdata...))}
	case rrType == D.TypeAAAA && rdLength == net.IPv6len:
		answer = &D.AAAA{Hdr: headerRR, AAAA: net.IP(append([]byte(nil), rdata...))}
	default:
		return nil, flags, code, nil
	}
	return mdnsReplyForRequest(request, answer), flags, code, nil
}

func mdnsReplyForRequest(request *D.Msg, answer D.RR) *D.Msg {
	response := &D.Msg{}
	response.SetReply(request)
	response.Authoritative = true
	response.Answer = []D.RR{answer}
	return response
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[n:]
	}
	return nil
}

func isTimeoutError(err error) bool {
	var netError net.Error
	return errors.As(err, &netError) && netError.Timeout()
}
