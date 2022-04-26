package http

import (
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
	return strings.EqualFold(req.Header.Get("Connection"), "Upgrade")
}

func handleUpgrade(conn net.Conn, request *http.Request, in chan<- C.ConnContext) (resp *http.Response) {
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

	in <- inbound.NewHTTP(dstAddr, conn.RemoteAddr(), right)

	bufferedLeft := N.NewBufferedConn(left)
	defer func() {
		_ = bufferedLeft.Close()
	}()

	err := request.Write(bufferedLeft)
	if err != nil {
		return
	}

	resp, err = http.ReadResponse(bufferedLeft.Reader(), request)
	if err != nil {
		return
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		removeProxyHeaders(resp.Header)

		err = conn.SetReadDeadline(time.Time{})
		if err != nil {
			return
		}

		err = resp.Write(conn)
		if err != nil {
			return
		}

		N.Relay(bufferedLeft, conn)
		_ = conn.Close()
		resp = nil
	}
	return
}
