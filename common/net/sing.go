package net

import (
	"context"
	"net"

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
	if dc, ok := conn.(*deadline.Conn); ok {
		return dc
	}
	return deadline.NewConn(conn)
}

func NewDeadlinePacketConn(pc net.PacketConn) net.PacketConn {
	if dpc, ok := pc.(*deadline.PacketConn); ok {
		return dpc
	}
	return deadline.NewPacketConn(bufio.NewPacketConn(pc))
}

func NeedHandshake(conn any) bool {
	if earlyConn, isEarlyConn := common.Cast[network.EarlyConn](conn); isEarlyConn && earlyConn.NeedHandshake() {
		return true
	}
	return false
}

// Relay copies between left and right bidirectionally.
func Relay(leftConn, rightConn net.Conn) {
	_ = bufio.CopyConn(context.TODO(), leftConn, rightConn)
}
