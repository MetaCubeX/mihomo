package http2ping

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"

	C "github.com/metacubex/mihomo/constant"
	"golang.org/x/exp/constraints"
)

func dialProxyConn(ctx context.Context, p C.Proxy, targetUrlString string) (net.Conn, error) {
	addr, err := urlToMetadata(targetUrlString)
	if err != nil {
		return nil, err
	}
	return p.DialContext(ctx, &addr)
}

func urlToMetadata(rawURL string) (addr C.Metadata, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			err = fmt.Errorf("%s scheme not Support", rawURL)
			return
		}
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum > 65535 || portNum < 0 {
		err = fmt.Errorf("invalid port %s ", port)
		return
	}

	addr = C.Metadata{
		Host:    u.Hostname(),
		DstIP:   netip.Addr{},
		DstPort: uint16(portNum),
	}
	return
}

func Abs[T constraints.Signed](a T) T {
	if a < 0 {
		return -a
	}
	return a
}
