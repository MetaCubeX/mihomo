package adapters

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"strconv"

	C "github.com/Dreamacro/clash/constant"
	"github.com/riobard/go-shadowsocks2/socks"
)

func parseSocksAddr(target socks.Addr) *C.Addr {
	var host, port string
	var ip net.IP

	switch target[0] {
	case socks.AtypDomainName:
		host = string(target[2 : 2+target[1]])
		port = strconv.Itoa((int(target[2+target[1]]) << 8) | int(target[2+target[1]+1]))
		ipAddr, err := net.ResolveIPAddr("ip", host)
		if err == nil {
			ip = ipAddr.IP
		}
	case socks.AtypIPv4:
		ip = net.IP(target[1 : 1+net.IPv4len])
		port = strconv.Itoa((int(target[1+net.IPv4len]) << 8) | int(target[1+net.IPv4len+1]))
	case socks.AtypIPv6:
		ip = net.IP(target[1 : 1+net.IPv6len])
		port = strconv.Itoa((int(target[1+net.IPv6len]) << 8) | int(target[1+net.IPv6len+1]))
	}

	return &C.Addr{
		NetWork:  C.TCP,
		AddrType: int(target[0]),
		Host:     host,
		IP:       &ip,
		Port:     port,
	}
}

func parseHTTPAddr(request *http.Request) *C.Addr {
	host := request.URL.Hostname()
	port := request.URL.Port()
	if port == "" {
		port = "80"
	}
	ipAddr, err := net.ResolveIPAddr("ip", host)
	var resolveIP *net.IP
	if err == nil {
		resolveIP = &ipAddr.IP
	}

	var addType int
	ip := net.ParseIP(host)
	switch {
	case ip == nil:
		addType = socks.AtypDomainName
	case ip.To4() == nil:
		addType = socks.AtypIPv6
	default:
		addType = socks.AtypIPv4
	}

	return &C.Addr{
		NetWork:  C.TCP,
		AddrType: addType,
		Host:     host,
		IP:       resolveIP,
		Port:     port,
	}
}

// ParserHTTPHostHeader returns the HTTP Host header from br without
// consuming any of its bytes. It returns "" if it can't find one.
func ParserHTTPHostHeader(br *bufio.Reader) (method, host string) {
	// br := bufio.NewReader(bytes.NewReader(data))
	const maxPeek = 4 << 10
	peekSize := 0
	for {
		peekSize++
		if peekSize > maxPeek {
			b, _ := br.Peek(br.Buffered())
			return method, httpHostHeaderFromBytes(b)
		}
		b, err := br.Peek(peekSize)
		if n := br.Buffered(); n > peekSize {
			b, _ = br.Peek(n)
			peekSize = n
		}
		if len(b) > 0 {
			if b[0] < 'A' || b[0] > 'Z' {
				// Doesn't look like an HTTP verb
				// (GET, POST, etc).
				return
			}
			if bytes.Index(b, crlfcrlf) != -1 || bytes.Index(b, lflf) != -1 {
				println(string(b))
				req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
				if err != nil {
					return
				}
				if len(req.Header["Host"]) > 1 {
					// TODO(bradfitz): what does
					// ReadRequest do if there are
					// multiple Host headers?
					return
				}
				println(req.Host)
				return req.Method, req.Host
			}
		}
		if err != nil {
			return method, httpHostHeaderFromBytes(b)
		}
	}
}

var (
	lfHostColon = []byte("\nHost:")
	lfhostColon = []byte("\nhost:")
	crlf        = []byte("\r\n")
	lf          = []byte("\n")
	crlfcrlf    = []byte("\r\n\r\n")
	lflf        = []byte("\n\n")
)

func httpHostHeaderFromBytes(b []byte) string {
	if i := bytes.Index(b, lfHostColon); i != -1 {
		return string(bytes.TrimSpace(untilEOL(b[i+len(lfHostColon):])))
	}
	if i := bytes.Index(b, lfhostColon); i != -1 {
		return string(bytes.TrimSpace(untilEOL(b[i+len(lfhostColon):])))
	}
	return ""
}

// untilEOL returns v, truncated before the first '\n' byte, if any.
// The returned slice may include a '\r' at the end.
func untilEOL(v []byte) []byte {
	if i := bytes.IndexByte(v, '\n'); i != -1 {
		return v[:i]
	}
	return v
}
