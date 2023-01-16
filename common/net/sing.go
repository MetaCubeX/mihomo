package net

import (
	"context"
	"net"

	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/network"
)

var NewExtendedConn = bufio.NewExtendedConn
var NewExtendedWriter = bufio.NewExtendedWriter
var NewExtendedReader = bufio.NewExtendedReader

type ExtendedConn = network.ExtendedConn
type ExtendedWriter = network.ExtendedWriter
type ExtendedReader = network.ExtendedReader

// Relay copies between left and right bidirectionally.
func Relay(leftConn, rightConn net.Conn) {
	_ = bufio.CopyConn(context.TODO(), leftConn, rightConn)
}
