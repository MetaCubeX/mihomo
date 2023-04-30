package inner

import (
	"context"
	"net"

	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

var tcpIn chan<- C.ConnContext

func New(in chan<- C.ConnContext) {
	tcpIn = in
}

func HandleTcp(ctx context.Context, address string) (conn net.Conn, err error) {
	if tcpIn != nil {
		// executor Parsed
		conn1, conn2 := net.Pipe()
		context := inbound.NewInner(conn2, address, "")
		tcpIn <- context
		return conn1, nil
	}
	log.Debugln("[Inner] executor not prepared, using direct dial, target=%s", address)
	// At this point, no executor is available, so we need to
	// dial the target server directly
	return net.Dial("tcp", address)
}
