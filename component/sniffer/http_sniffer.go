package sniffer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/sniffer"

	"golang.org/x/net/http2/hpack"
)

var (
	errNotHTTP  = errors.New("not an HTTP")
	errHostIsIP = errors.New("host is ip")
)

// RFC 9110 §9.3
// RFC 5789 (PATCH method)
var httpMethods = [...][]byte{
	[]byte("GET"), []byte("POST"), []byte("HEAD"), []byte("PUT"),
	[]byte("DELETE"), []byte("OPTIONS"), []byte("CONNECT"), []byte("PATCH"), []byte("TRACE"),
}

// RFC 9113 §3.4
var h2ClientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// RFC 9113 §4.1
const h2FrameHeaderLen = 9

// RFC 9113 §6.2 / §6.10
const (
	h2FrameHeaders      byte = 0x1
	h2FrameSettings     byte = 0x4
	h2FrameContinuation byte = 0x9

	h2FlagAck        byte = 0x1
	h2FlagEndHeaders byte = 0x4
	h2FlagPadded     byte = 0x8
	h2FlagPriority   byte = 0x20
)

const (
	// RFC 9113 §6.5.2
	headerTableSize uint32 = 4096
	// RFC 9113 §4.2
	h2DefaultMaxFrameSize = 1 << 14
)

type HTTPSniffer struct {
	*BaseSniffer
}

var _ sniffer.Sniffer = (*HTTPSniffer)(nil)

func NewHTTPSniffer(snifferConfig SnifferConfig) (*HTTPSniffer, error) {
	ports := snifferConfig.Ports
	if len(ports) == 0 {
		ports = utils.IntRanges[uint16]{utils.NewRange[uint16](80, 80)}
	}
	return &HTTPSniffer{
		BaseSniffer: NewBaseSniffer(ports, C.TCP),
	}, nil
}

func (http *HTTPSniffer) Protocol() string {
	return "http"
}

func (http *HTTPSniffer) SupportNetwork() C.NetWork {
	return C.TCP
}

func (http *HTTPSniffer) SniffData(b []byte) (string, error) {
	if len(b) < len(h2ClientPreface) {
		if bytes.HasPrefix(h2ClientPreface, b) {
			// Advance incrementally so a mismatch can fall back to HTTP/1
			// without waiting for the entire preface.
			return "", &errNeedAtLeastData{length: len(b) + 1, err: ErrNoClue}
		}
		return sniffHTTP1(b)
	}
	if bytes.HasPrefix(b, h2ClientPreface) {
		return sniffHTTP2(b)
	}
	return sniffHTTP1(b)
}

func isHTTPMethod(method []byte) bool {
	for _, m := range httpMethods {
		if bytes.EqualFold(method, m) {
			return true
		}
	}
	return false
}

func isHTTPMethodPrefix(prefix []byte) bool {
	for _, method := range httpMethods {
		if len(prefix) <= len(method) && bytes.EqualFold(prefix, method[:len(prefix)]) {
			return true
		}
	}
	return false
}

func sniffHTTP1(b []byte) (string, error) {
	method, _, found := bytes.Cut(b, []byte(" "))
	if !found {
		if isHTTPMethodPrefix(b) {
			return "", &errNeedAtLeastData{length: len(b) + 1, err: ErrNoClue}
		}
		return "", errNotHTTP
	}
	if !isHTTPMethod(method) {
		return "", errNotHTTP
	}

	req, _, found := bytes.Cut(b, []byte("\r\n"))
	if !found {
		return "", &errNeedAtLeastData{
			length: len(b) + 1,
			err:    ErrNoClue,
		}
	}
	if len(req) < 14 {
		return "", ErrNoClue
	}

	_, rest, ok1 := bytes.Cut(req, []byte(" "))
	uri, _, ok2 := bytes.Cut(rest, []byte(" "))
	if !ok1 || !ok2 {
		return "", ErrNoClue
	}
	if len(uri) == 0 {
		return "", ErrNoClue
	}

	switch uri[0] {
	// RFC 9112 §3.2.1 / §3.2.4
	case '/', '*':
		return parseHeaderHostH1(b)
	default:
		// RFC 9112 §3.2.2
		if _, afterScheme, found := bytes.Cut(uri, []byte("://")); found {
			uri = afterScheme
		}

		// RFC 3986 §3.2
		if i := bytes.IndexAny(uri, "/?#"); i >= 0 {
			uri = uri[:i]
		}
		if _, afterAt, found := bytes.Cut(uri, []byte("@")); found {
			uri = afterAt
		}

		h, err := parseHost(uri)
		if err != nil {
			return parseHeaderHostH1(b)
		}

		return h, nil
	}
}

func parseHeaderHostH1(b []byte) (string, error) {
	rest := b
	for {
		line, tail, found := bytes.Cut(rest, []byte("\r\n"))
		if !found {
			return "", &errNeedAtLeastData{length: len(b) + 1, err: ErrNoClue}
		}
		if len(line) == 0 {
			return "", ErrNoClue
		}
		rest = tail
		key, val, found := bytes.Cut(line, []byte(":"))
		if !found || !bytes.EqualFold(key, []byte("host")) { // RFC 9110 §7.2
			continue
		}
		// A complete Host field is sufficient; waiting for the end of the
		// header section would make unrelated large fields delay sniffing.
		return parseHost(bytes.TrimSpace(val))
	}
}

func sniffHTTP2(b []byte) (string, error) {
	total := len(b)
	b = b[len(h2ClientPreface):]

	// RFC 9113 §8.3.1
	var (
		authority      string
		host           string
		headerStreamID uint32
	)
	decoder := hpack.NewDecoder(headerTableSize, func(f hpack.HeaderField) {
		switch f.Name {
		case ":authority":
			authority = f.Value
		case "host":
			host = f.Value
		}
	})

	for { // RFC 9113 §4.1
		if len(b) < h2FrameHeaderLen {
			return "", &errNeedAtLeastData{
				length: total - len(b) + h2FrameHeaderLen,
				err:    ErrNoClue,
			}
		}

		length := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		frameType := b[3]
		flags := b[4]
		streamID := binary.BigEndian.Uint32(b[5:9]) & 0x7fffffff

		b = b[h2FrameHeaderLen:]
		payloadOffset := total - len(b)
		if payloadOffset == len(h2ClientPreface)+h2FrameHeaderLen {
			// The client connection preface is followed by a non-ACK SETTINGS
			// frame. Rejecting another type here avoids waiting for a payload
			// that cannot make this a valid HTTP/2 connection.
			if frameType != h2FrameSettings || flags&h2FlagAck != 0 {
				return "", ErrNoClue
			}
		}
		if length > h2DefaultMaxFrameSize {
			// No server SETTINGS can have been received while sniffing holds the
			// connection, so the RFC-defined default frame size still applies.
			return "", ErrNoClue
		}
		if frameType == h2FrameSettings {
			ack := flags&h2FlagAck != 0
			if streamID != 0 || ack && length != 0 || !ack && length%6 != 0 {
				return "", ErrNoClue
			}
		}
		if headerStreamID == 0 {
			if frameType == h2FrameContinuation {
				return "", ErrNoClue
			}
			if frameType == h2FrameHeaders && streamID == 0 {
				return "", ErrNoClue
			}
		} else if frameType != h2FrameContinuation || streamID != headerStreamID {
			// RFC 9113 §4.3 requires a header block's CONTINUATION frames to be
			// contiguous and use the same stream identifier. The frame header is
			// sufficient to reject a violation without waiting for its payload.
			return "", ErrNoClue
		}

		if headerStreamID == 0 {
			if frameType != h2FrameHeaders {
				if len(b) < length {
					return "", &errNeedAtLeastData{length: payloadOffset + length, err: ErrNoClue}
				}
				b = b[length:]
				continue
			}
			headerStreamID = streamID
		}

		fragmentStart := 0
		fragmentEnd := length
		if frameType == h2FrameHeaders {
			if flags&h2FlagPadded != 0 {
				if length == 0 {
					return "", ErrNoClue
				}
				if len(b) == 0 {
					return "", &errNeedAtLeastData{length: payloadOffset + 1, err: ErrNoClue}
				}
				padLen := int(b[0])
				if padLen >= length {
					return "", ErrNoClue
				}
				fragmentStart++
				fragmentEnd -= padLen
			}

			if flags&h2FlagPriority != 0 {
				if fragmentEnd-fragmentStart < 5 {
					return "", ErrNoClue
				}
				fragmentStart += 5
			}
		}

		availableEnd := len(b)
		if availableEnd > fragmentEnd {
			availableEnd = fragmentEnd
		}
		if availableEnd > fragmentStart {
			_, err := decoder.Write(b[fragmentStart:availableEnd])
			// A complete authority field is enough for routing. Like HTTP/1 Host,
			// later fields cannot improve the sniffing result and must not delay it.
			if authority != "" {
				return parseHost([]byte(authority))
			}
			if host != "" {
				return parseHost([]byte(host))
			}
			if err != nil {
				return "", ErrNoClue
			}
		}
		if flags&h2FlagEndHeaders != 0 && (fragmentStart == fragmentEnd || availableEnd == fragmentEnd) {
			// The HPACK fragment is complete or known to be empty. Trailing frame
			// padding cannot contain a host and therefore cannot change the verdict.
			return "", ErrNoClue
		}

		if len(b) < length {
			want := payloadOffset + length
			if availableEnd < fragmentEnd {
				// More HPACK bytes may complete the authority before the rest of
				// this frame, so advance only to the next byte that can help.
				want = total + 1
				if len(b) < fragmentStart {
					want = payloadOffset + fragmentStart + 1
				}
			}
			return "", &errNeedAtLeastData{length: want, err: ErrNoClue}
		}
		b = b[length:]
		continue
	}
}

func parseHost(h []byte) (string, error) {
	if len(h) == 0 {
		return "", ErrNoClue
	}
	hs := string(h)

	// RFC 3986 §3.2.3
	// strip port
	if host, _, err := net.SplitHostPort(hs); err == nil {
		hs = host
	}

	// RFC 3986 §3.2.2
	// reject IPv6
	if strings.HasPrefix(hs, "[") && strings.HasSuffix(hs, "]") {
		hs = hs[1 : len(hs)-1]
	}

	// strip dot
	// for example: example.com. -> example.com
	hs = strings.ToLower(strings.TrimRight(hs, "."))
	if hs == "" {
		return "", ErrNoClue
	}

	if _, err := netip.ParseAddr(hs); err == nil {
		return "", errHostIsIP
	}

	return hs, nil
}
