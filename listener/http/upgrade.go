package http

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
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

func handleUpgrade(conn net.Conn, request *http.Request, tunnel C.Tunnel, additions ...inbound.Addition) {
	defer conn.Close()

	removeProxyHeaders(request.Header)
	removeExtraHTTPHostPort(request)

	address := request.Host
	if _, _, err := net.SplitHostPort(address); err != nil {
		address = net.JoinHostPort(address, "80")
	}

	dstAddr := socks5.ParseAddr(address)
	if dstAddr == nil {
		return
	}

	left, right := N.Pipe()

	go tunnel.HandleTCPConn(inbound.NewHTTP(dstAddr, conn, right, additions...))

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
