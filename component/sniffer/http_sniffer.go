package sniffer

import (
	"bytes"
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

// RFC 9113 §6.2
const (
	h2FrameHeaders byte = 0x1

	h2FlagPadded   byte = 0x8
	h2FlagPriority byte = 0x20
)

// RFC 9113 §6.5.2
const headerTableSize uint32 = 4096

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
			return "", &errNeedAtLeastData{length: len(h2ClientPreface), err: ErrNoClue}
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

func sniffHTTP1(b []byte) (string, error) {
	req, _, found := bytes.Cut(b, []byte("\r\n"))
	if !found {
		return "", &errNeedAtLeastData{
			length: len(b) + 1,
			err: ErrNoClue,
		}
	}
	if len(req) < 14 {
		return "", ErrNoClue
	}

	method, rest, ok1 := bytes.Cut(req, []byte(" "))
	uri, _, ok2 := bytes.Cut(rest, []byte(" "))
	if !ok1 || !ok2 {
		return "", ErrNoClue
	}
	if !isHTTPMethod(method) {
		return "", errNotHTTP
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
	if !bytes.Contains(b, []byte("\r\n\r\n")) {
		return "", &errNeedAtLeastData{length: len(b) + 1, err: ErrNoClue}
	}
	rest := b
	for {
		line, tail, found := bytes.Cut(rest, []byte("\r\n"))
		if !found || len(line) == 0 {
			break
		}
		rest = tail
		key, val, found := bytes.Cut(line, []byte(":"))
		if !found || !bytes.EqualFold(key, []byte("host")) { // RFC 9110 §7.2
			continue
		}
		return parseHost(bytes.TrimSpace(val))
	}
	return "", ErrNoClue
}

func sniffHTTP2(b []byte) (string, error) {
	total := len(b)
	b = b[len(h2ClientPreface):]

	var (
		payload []byte
		flags   byte
	)
	for { // RFC 9113 §4.1
		if len(b) < 9 {
			return "", &errNeedAtLeastData{
				length: total - len(b) + 9,
				err: ErrNoClue,
			}
		}

		length := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		frameType := b[3]
		flags = b[4]

		b = b[9:]

		if len(b) < length {
			return "", &errNeedAtLeastData{
				length: total - len(b) + length,
				err: ErrNoClue,
			}
		}
		if frameType == h2FrameHeaders {
			payload = b[:length]
			break
		}

		b = b[length:]
	}

	if flags&h2FlagPadded != 0 {
		if len(payload) == 0 {
			return "", ErrNoClue
		}
		padLen := int(payload[0])
		if padLen >= len(payload) {
			return "", ErrNoClue
		}
		payload = payload[1 : len(payload)-padLen]
	}

	if flags&h2FlagPriority != 0 {
		if len(payload) < 5 {
			return "", ErrNoClue
		}
		payload = payload[5:]
	}

	// RFC 9113 §8.3.1
	var (
		authority string
		host      string
	)
	decoder := hpack.NewDecoder(headerTableSize, func(f hpack.HeaderField) {
		switch f.Name {
		case ":authority":
			authority = f.Value
		case "host":
			host = f.Value
		}
	})

	_, err := decoder.Write(payload)
	if err != nil {
		return "", ErrNoClue
	}

	if authority == "" {
		if host == "" {
			return "", ErrNoClue
		}
		authority = host
	}

	return parseHost([]byte(authority))
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
	hs = strings.TrimRight(hs, ".")
	if hs == "" {
		return "", ErrNoClue
	}

	if _, err := netip.ParseAddr(hs); err == nil {
		return "", errHostIsIP
	}

	return hs, nil
}
