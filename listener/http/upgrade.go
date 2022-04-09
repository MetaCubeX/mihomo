package http

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Dreamacro/clash/adapter/inbound"
	N "github.com/Dreamacro/clash/common/net"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
)

func isUpgradeRequest(req *http.Request) bool {
	for _, header := range req.Header["Connection"] {
		for _, elm := range strings.Split(header, ",") {
			if strings.EqualFold(strings.TrimSpace(elm), "Upgrade") {
				return true
			}
		}
	}

	return false
}

func handleUpgrade(conn net.Conn, request *http.Request, in chan<- C.ConnContext, additions ...inbound.Addition) {
	defer conn.Close()

	removeProxyHeaders(request.Header)
	RemoveExtraHTTPHostPort(request)

	address := request.Host
	if _, _, err := net.SplitHostPort(address); err != nil {
		address = net.JoinHostPort(address, "80")
	}

	dstAddr := socks5.ParseAddr(address)
	if dstAddr == nil {
		return
	}

	left, right := net.Pipe()

	in <- inbound.NewHTTP(dstAddr, conn.RemoteAddr(), right, additions...)

	var bufferedLeft *N.BufferedConn
	if request.TLS != nil {
		tlsConn := tls.Client(left, &tls.Config{
			ServerName: request.URL.Hostname(),
		})

		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
		defer cancel()
		if tlsConn.HandshakeContext(ctx) != nil {
			_ = left.Close()
			return
		}

		bufferedLeft = N.NewBufferedConn(tlsConn)
	} else {
		bufferedLeft = N.NewBufferedConn(left)
	}
	defer func() {
		_ = bufferedLeft.Close()
	}()

	err := request.Write(bufferedLeft)
	if err != nil {
		return
	}

	resp, err := http.ReadResponse(bufferedLeft.Reader(), request)
	if err != nil {
		return
	}

	removeProxyHeaders(resp.Header)

	err = resp.Write(conn)
	if err != nil {
		return
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		N.Relay(bufferedLeft, conn)
	}
}

func HandleUpgradeY(localConn net.Conn, serverConn *N.BufferedConn, request *http.Request, in chan<- C.ConnContext) (resp *http.Response) {
	removeProxyHeaders(request.Header)
	RemoveExtraHTTPHostPort(request)

	if serverConn == nil {
		address := request.Host
		if _, _, err := net.SplitHostPort(address); err != nil {
			port := "80"
			if request.TLS != nil {
				port = "443"
			}
			address = net.JoinHostPort(address, port)
		}

		dstAddr := socks5.ParseAddr(address)
		if dstAddr == nil {
			return
		}

		left, right := net.Pipe()

		in <- inbound.NewHTTP(dstAddr, localConn.RemoteAddr(), right)

		serverConn = N.NewBufferedConn(left)

		defer func() {
			_ = serverConn.Close()
		}()
	}

	err := request.Write(serverConn)
	if err != nil {
		_ = localConn.Close()
		return
	}

	resp, err = http.ReadResponse(serverConn.Reader(), request)
	if err != nil {
		_ = localConn.Close()
		return
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		removeProxyHeaders(resp.Header)

		err = localConn.SetReadDeadline(time.Time{}) // set to not time out
		if err != nil {
			return
		}

		err = resp.Write(localConn)
		if err != nil {
			return
		}

		N.Relay(serverConn, localConn) // blocking here
		_ = localConn.Close()
		resp = nil
	}
	return
}
