package net

import (
	"errors"
	"io"
	"net"

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

// CloseReset resets the connection if supported before closing it.
func CloseReset(conn net.Conn) error {
	if conn == nil {
		return nil
	}
	if lingerConn, ok := common.Cast[interface{ SetLinger(int) error }](conn); ok {
		_ = lingerConn.SetLinger(0)
	}
	return conn.Close()
}

func isNormalClose(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}

// Relay copies between left and right bidirectionally.
// If resetLeftOnError is true, copy errors reset the left connection when supported.
// like [bufio.CopyConn] but remove unneeded [context.Context] handle and the cost of [task.Group]
func Relay(leftConn, rightConn net.Conn, resetLeftOnError ...bool) {
	resetLeft := len(resetLeftOnError) > 0 && resetLeftOnError[0]
	defer func() {
		_ = leftConn.Close()
		_ = rightConn.Close()
	}()

	ch := make(chan struct{})
	go func() {
		_, err := bufio.Copy(leftConn, rightConn)
		if isNormalClose(err) {
			_ = closeWrite(leftConn)
		} else {
			if resetLeft {
				_ = CloseReset(leftConn)
			} else {
				_ = leftConn.Close()
			}
		}
		close(ch)
	}()

	_, err := bufio.Copy(rightConn, leftConn)
	if isNormalClose(err) {
		_ = closeWrite(rightConn)
	} else {
		if resetLeft {
			_ = CloseReset(leftConn)
		}
		_ = rightConn.Close()
	}
	<-ch
}
