package http

import (
	"net"
	"net/http"
	"strings"

	"github.com/Dreamacro/clash/adapter/inbound"
	N "github.com/Dreamacro/clash/common/net"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
)

func isUpgradeRequest(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get("Connection"), "Upgrade")
}

func handleUpgrade(conn net.Conn, request *http.Request, in chan<- C.ConnContext) {
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

	left, right := net.Pipe()

	in <- inbound.NewHTTP(dstAddr, conn.RemoteAddr(), right)

	bufferedLeft := N.NewBufferedConn(left)
	defer bufferedLeft.Close()

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
