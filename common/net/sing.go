package net

import (
	"context"
	"net"
	"runtime"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/bufio/deadline"
	"github.com/sagernet/sing/common/network"
)

var NewExtendedConn = bufio.NewExtendedConn
var NewExtendedWriter = bufio.NewExtendedWriter
var NewExtendedReader = bufio.NewExtendedReader

type ExtendedConn = network.ExtendedConn
type ExtendedWriter = network.ExtendedWriter
type ExtendedReader = network.ExtendedReader

func NewDeadlineConn(conn net.Conn) ExtendedConn {
	return deadline.NewFallbackConn(conn)
}

func NewDeadlinePacketConn(pc net.PacketConn) network.NetPacketConn {
	return deadline.NewFallbackPacketConn(bufio.NewPacketConn(pc))
}

func NeedHandshake(conn any) bool {
	if earlyConn, isEarlyConn := common.Cast[network.EarlyConn](conn); isEarlyConn && earlyConn.NeedHandshake() {
		return true
	}
	return false
}

type CountFunc = network.CountFunc

// Relay copies between left and right bidirectionally.
func Relay(leftConn, rightConn net.Conn) {
	defer runtime.KeepAlive(leftConn)
	defer runtime.KeepAlive(rightConn)
	_ = bufio.CopyConn(context.TODO(), leftConn, rightConn)
}
