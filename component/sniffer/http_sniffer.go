package sniffer

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/Dreamacro/clash/common/utils"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/sniffer"
)

var (
	// refer to https://pkg.go.dev/net/http@master#pkg-constants
	methods          = [...]string{"get", "post", "head", "put", "delete", "options", "connect", "patch", "trace"}
	errNotHTTPMethod = errors.New("not an HTTP method")
)

type version byte

const (
	HTTP1 version = iota
	HTTP2
)

type HTTPSniffer struct {
	*BaseSniffer
	version version
	host    string
}

var _ sniffer.Sniffer = (*HTTPSniffer)(nil)

func NewHTTPSniffer(snifferConfig SnifferConfig) (*HTTPSniffer, error) {
	ports := make([]utils.Range[uint16], 0)
	if len(snifferConfig.Ports) == 0 {
		ports = append(ports, *utils.NewRange[uint16](80, 80))
	} else {
		ports = append(ports, snifferConfig.Ports...)
	}
	return &HTTPSniffer{
		BaseSniffer: NewBaseSniffer(ports, C.TCP),
	}, nil
}

func (http *HTTPSniffer) Protocol() string {
	switch http.version {
	case HTTP1:
		return "http1"
	case HTTP2:
		return "http2"
	default:
		return "unknown"
	}
}

func (http *HTTPSniffer) SupportNetwork() C.NetWork {
	return C.TCP
}

func (http *HTTPSniffer) SniffTCP(bytes []byte) (string, error) {
	domain, err := SniffHTTP(bytes)
	if err == nil {
		return *domain, nil
	} else {
		return "", err
	}
}

func beginWithHTTPMethod(b []byte) error {
	for _, m := range &methods {
		if len(b) >= len(m) && strings.EqualFold(string(b[:len(m)]), m) {
			return nil
		}

		if len(b) < len(m) {
			return ErrNoClue
		}
	}
	return errNotHTTPMethod
}

func SniffHTTP(b []byte) (*string, error) {
	if err := beginWithHTTPMethod(b); err != nil {
		return nil, err
	}

	_ = &HTTPSniffer{
		version: HTTP1,
	}

	headers := bytes.Split(b, []byte{'\n'})
	for i := 1; i < len(headers); i++ {
		header := headers[i]
		if len(header) == 0 {
			break
		}
		parts := bytes.SplitN(header, []byte{':'}, 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(string(parts[0]))
		if key == "host" {
			rawHost := strings.ToLower(string(bytes.TrimSpace(parts[1])))
			host, _, err := net.SplitHostPort(rawHost)
			if err != nil {
				if addrError, ok := err.(*net.AddrError); ok && strings.Contains(addrError.Err, "missing port") {
					return parseHost(rawHost)
				} else {
					return nil, err
				}
			}

			if net.ParseIP(host) != nil {
				return nil, fmt.Errorf("host is ip")
			}

			return &host, nil
		}
	}
	return nil, ErrNoClue
}

func parseHost(host string) (*string, error) {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		if net.ParseIP(host[1:len(host)-1]) != nil {
			return nil, fmt.Errorf("host is ip")
		}
	}

	if net.ParseIP(host) != nil {
		return nil, fmt.Errorf("host is ip")
	}

	return &host, nil
}
