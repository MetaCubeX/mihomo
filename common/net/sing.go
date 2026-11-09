package net

import (
	"io"
	"net"
	"sync/atomic"

	"github.com/metacubex/mihomo/common/net/deadline"

	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/bufio"
	"github.com/metacubex/sing/common/network"
)

var NewExtendedConn = bufio.NewExtendedConn
var NewExtendedWriter = bufio.NewExtendedWriter
var NewExtendedReader = bufio.NewExtendedReader

type ExtendedConn = network.ExtendedConn
type ExtendedWriter = network.ExtendedWriter
type ExtendedReader = network.ExtendedReader

var WriteBuffer = bufio.WriteBuffer

type ReadWaitOptions = network.ReadWaitOptions

var NewReadWaitOptions = network.NewReadWaitOptions
var CalculateFrontHeadroom = network.CalculateFrontHeadroom
var CalculateRearHeadroom = network.CalculateRearHeadroom

type ReaderWithUpstream = network.ReaderWithUpstream
type WithUpstreamReader = network.WithUpstreamReader
type WriterWithUpstream = network.WriterWithUpstream
type WithUpstreamWriter = network.WithUpstreamWriter
type WithUpstream = common.WithUpstream

var UnwrapReader = network.UnwrapReader
var UnwrapWriter = network.UnwrapWriter

func NewDeadlineConn(conn net.Conn) ExtendedConn {
	if deadline.IsPipe(conn) || deadline.IsPipe(UnwrapReader(conn)) {
		return NewExtendedConn(conn) // pipe always have correctly deadline implement
	}
	if deadline.IsConn(conn) || deadline.IsConn(UnwrapReader(conn)) {
		return NewExtendedConn(conn) // was a *deadline.Conn
	}
	return deadline.NewConn(conn)
}

func NeedHandshake(conn any) bool {
	if earlyConn, isEarlyConn := common.Cast[network.EarlyConn](conn); isEarlyConn && earlyConn.NeedHandshake() {
		return true
	}
	return false
}

type CountFunc = network.CountFunc

var Pipe = deadline.Pipe

func closeWrite(writer io.Closer) error {
	if c, ok := common.Cast[network.WriteCloser](writer); ok {
		return c.CloseWrite()
	}
	return writer.Close()
}

// Relay copies between left and right bidirectionally.
// If resetLeftOnError is true, copy errors reset the left connection when supported.
// like [bufio.CopyConn] but remove unneeded [context.Context] handle and the cost of [task.Group]
func Relay(leftConn, rightConn net.Conn, resetLeftOnError ...bool) {
	var lingerConn interface{ SetLinger(int) error }
	if len(resetLeftOnError) > 0 && resetLeftOnError[0] {
		lingerConn, _ = common.Cast[interface{ SetLinger(int) error }](leftConn)
	}
	defer func() {
		_ = leftConn.Close()
		_ = rightConn.Close()
	}()

	var closingOutboundAfterEOF atomic.Bool
	ch := make(chan struct{})
	go func() {
		_, err := bufio.Copy(leftConn, rightConn)
		if err == nil {
			_ = closeWrite(leftConn)
		} else {
			if lingerConn != nil && !closingOutboundAfterEOF.Load() {
				_ = lingerConn.SetLinger(0)
			}
			_ = leftConn.Close()
		}
		close(ch)
	}()

	_, err := bufio.Copy(rightConn, leftConn)
	if err == nil {
		if c, ok := common.Cast[network.WriteCloser](rightConn); ok {
			_ = c.CloseWrite()
		} else {
			// Closing the whole outbound can interrupt the reverse copy.
			closingOutboundAfterEOF.Store(true)
			_ = rightConn.Close()
		}
	} else {
		if lingerConn != nil {
			// Reset the inbound before closing the outbound can make the reverse copy see EOF.
			_ = lingerConn.SetLinger(0)
			_ = leftConn.Close()
		}
		_ = rightConn.Close()
	}
	<-ch
}
