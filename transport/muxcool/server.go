package muxcool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/sing/common/auth"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

const (
	defaultXUDPIdleTimeout       = time.Minute
	defaultMaxSessionsPerCarrier = 1024
)

var (
	ErrServerClosed       = errors.New("mux.cool server is closed")
	ErrDuplicateSessionID = errors.New("mux.cool duplicate session ID")
	ErrSessionQueueFull   = errors.New("mux.cool session receive queue is full")
)

type ServerHandler interface {
	NewConnection(context.Context, net.Conn, M.Metadata) error
	NewPacketConnection(context.Context, N.PacketConn, M.Metadata) error
}

type ServerTimer interface {
	Stop() bool
}

type ServerOptions struct {
	XUDPIdleTimeout       time.Duration
	MaxSessionsPerCarrier int
	AfterFunc             func(time.Duration, func()) ServerTimer
}

type ServerRuntime struct {
	options ServerOptions

	mu       sync.Mutex
	closed   bool
	carriers map[*serverCarrier]struct{}
	flows    map[xudpFlowKey]*serverPacketFlow
	wg       sync.WaitGroup
	close    sync.Once
}

func NewServerRuntime(options ServerOptions) *ServerRuntime {
	if options.XUDPIdleTimeout <= 0 {
		options.XUDPIdleTimeout = defaultXUDPIdleTimeout
	}
	if options.MaxSessionsPerCarrier <= 0 {
		options.MaxSessionsPerCarrier = defaultMaxSessionsPerCarrier
	}
	if options.AfterFunc == nil {
		options.AfterFunc = func(duration time.Duration, callback func()) ServerTimer {
			return time.AfterFunc(duration, callback)
		}
	}
	return &ServerRuntime{
		options:  options,
		carriers: make(map[*serverCarrier]struct{}),
		flows:    make(map[xudpFlowKey]*serverPacketFlow),
	}
}

func (r *ServerRuntime) Serve(ctx context.Context, conn net.Conn, metadata M.Metadata, handler ServerHandler) error {
	carrier := newServerCarrier(r, ctx, conn, metadata, handler)
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = conn.Close()
		return ErrServerClosed
	}
	r.carriers[carrier] = struct{}{}
	r.wg.Add(1)
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		delete(r.carriers, carrier)
		r.mu.Unlock()
		r.wg.Done()
	}()
	return carrier.serve()
}

func (r *ServerRuntime) Close() error {
	r.close.Do(func() {
		r.mu.Lock()
		r.closed = true
		carriers := make([]*serverCarrier, 0, len(r.carriers))
		for carrier := range r.carriers {
			carriers = append(carriers, carrier)
		}
		flows := make([]*serverPacketFlow, 0, len(r.flows))
		for _, flow := range r.flows {
			flows = append(flows, flow)
		}
		r.mu.Unlock()

		for _, carrier := range carriers {
			carrier.closeWithError(ErrServerClosed)
		}
		for _, flow := range flows {
			flow.closeWithError(ErrServerClosed)
		}
		r.wg.Wait()
	})
	return nil
}

type xudpFlowKey struct {
	principal string
	globalID  [8]byte
}

func (r *ServerRuntime) attachXUDP(
	ctx context.Context,
	carrier *serverCarrier,
	frame decodedFrame,
) (*serverPacketAttachment, error) {
	key := xudpFlowKey{principal: serverPrincipal(ctx, carrier.metadata), globalID: frame.GlobalID}
	destination := socksaddrFromFrame(frame.Frame)

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		frame.releasePayload()
		return nil, ErrServerClosed
	}
	flow := r.flows[key]
	if flow == nil {
		flowContext, cancel := context.WithCancelCause(context.WithoutCancel(ctx))
		flow = newServerPacketFlow(r, key, flowContext, cancel, carrier.handler, carrier.metadata.Source, destination, true)
		r.flows[key] = flow
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			flow.runHandler()
		}()
	} else if flow.destination != destination {
		r.mu.Unlock()
		frame.releasePayload()
		return nil, fmt.Errorf("mux.cool XUDP GlobalID target mismatch: have %s, got %s", flow.destination, destination)
	}
	r.mu.Unlock()

	attachment, err := flow.attach(carrier, frame.SessionID)
	if err != nil {
		frame.releasePayload()
		return nil, err
	}
	return attachment, nil
}

func (r *ServerRuntime) removeFlow(key xudpFlowKey, flow *serverPacketFlow) {
	r.mu.Lock()
	if r.flows[key] == flow {
		delete(r.flows, key)
	}
	r.mu.Unlock()
}

func serverPrincipal(ctx context.Context, metadata M.Metadata) string {
	if user, loaded := auth.UserFromContext[string](ctx); loaded {
		return "user:" + user
	}
	return "source:" + metadata.Source.String()
}

type serverSession interface {
	deliverDecodedFrame(decodedFrame) error
	finish(error, bool)
}

type serverCarrier struct {
	runtime  *ServerRuntime
	ctx      context.Context
	cancel   context.CancelCauseFunc
	conn     net.Conn
	metadata M.Metadata
	handler  ServerHandler

	writeMu     sync.Mutex
	writeBuffer []byte
	mu          sync.Mutex
	sessions    map[uint16]serverSession
	closed      bool
	closeErr    error
	closeOnce   sync.Once
}

func newServerCarrier(runtime *ServerRuntime, parent context.Context, conn net.Conn, metadata M.Metadata, handler ServerHandler) *serverCarrier {
	ctx, cancel := context.WithCancelCause(parent)
	return &serverCarrier{
		runtime:  runtime,
		ctx:      ctx,
		cancel:   cancel,
		conn:     conn,
		metadata: metadata,
		handler:  handler,
		sessions: make(map[uint16]serverSession),
	}
}

func (c *serverCarrier) serve() error {
	ctxDone := c.ctx.Done()
	if ctxDone != nil {
		go func() {
			<-ctxDone
			c.closeWithError(context.Cause(c.ctx))
		}()
	}

	metadataBuffer := make([]byte, MaxMetadataSize)
	for {
		frame, err := decodeFramePooled(c.conn, metadataBuffer)
		if err != nil {
			c.closeWithError(err)
			return err
		}
		if err := c.handleFrame(frame); err != nil {
			c.closeWithError(err)
			return err
		}
	}
}

func (c *serverCarrier) handleFrame(frame decodedFrame) error {
	switch frame.Status {
	case StatusKeepAlive:
		frame.releasePayload()
		return nil
	case StatusNew:
		return c.handleNew(frame)
	case StatusKeep, StatusEnd:
		c.mu.Lock()
		session := c.sessions[frame.SessionID]
		c.mu.Unlock()
		if session == nil {
			frame.releasePayload()
			if frame.Status != StatusEnd {
				return c.writeFrame(Frame{SessionID: frame.SessionID, Status: StatusEnd, Option: OptionError})
			}
			return nil
		}
		if frame.Status == StatusEnd {
			frame.releasePayload()
			session.finish(remoteFrameError(frame.Frame), false)
			return nil
		}
		if err := session.deliverDecodedFrame(frame); err != nil {
			session.finish(err, true)
		}
		return nil
	default:
		frame.releasePayload()
		return protocolError("server", fmt.Errorf("invalid status %d", frame.Status))
	}
}

func (c *serverCarrier) handleNew(frame decodedFrame) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		frame.releasePayload()
		return net.ErrClosed
	}
	if _, exists := c.sessions[frame.SessionID]; exists {
		c.mu.Unlock()
		frame.releasePayload()
		return c.writeFrame(Frame{SessionID: frame.SessionID, Status: StatusEnd, Option: OptionError})
	}
	if len(c.sessions) >= c.runtime.options.MaxSessionsPerCarrier {
		c.mu.Unlock()
		frame.releasePayload()
		return c.writeFrame(Frame{SessionID: frame.SessionID, Status: StatusEnd, Option: OptionError})
	}
	// Reserve the peer-controlled ID before any handler or flow work.
	c.sessions[frame.SessionID] = nil
	c.mu.Unlock()

	var (
		session serverSession
		err     error
	)
	switch frame.Network {
	case NetworkTCP:
		session = newServerStream(c, frame.SessionID, socksaddrFromFrame(frame.Frame))
		if !c.publishReserved(frame.SessionID, session) {
			frame.releasePayload()
			err = net.ErrClosed
		} else if err = session.deliverDecodedFrame(frame); err == nil {
			session.(*serverStream).start()
		}
	case NetworkUDP:
		if frame.GlobalID != [8]byte{} {
			var attachment *serverPacketAttachment
			attachment, err = c.runtime.attachXUDP(c.ctx, c, frame)
			if err == nil {
				session = attachment
				if !c.publishReserved(frame.SessionID, session) {
					frame.releasePayload()
					err = net.ErrClosed
				} else {
					err = session.deliverDecodedFrame(frame)
				}
			}
		} else {
			flowContext, cancel := context.WithCancelCause(c.ctx)
			flow := newServerPacketFlow(nil, xudpFlowKey{}, flowContext, cancel, c.handler, c.metadata.Source, socksaddrFromFrame(frame.Frame), false)
			session, err = flow.attach(c, frame.SessionID)
			if err == nil {
				if !c.publishReserved(frame.SessionID, session) {
					frame.releasePayload()
					err = net.ErrClosed
				} else if err = session.deliverDecodedFrame(frame); err == nil {
					go flow.runHandler()
				}
			}
		}
	default:
		frame.releasePayload()
		err = protocolError("server new", fmt.Errorf("invalid network %d", frame.Network))
	}
	if err != nil {
		c.removeReserved(frame.SessionID)
		if session != nil {
			session.finish(err, true)
		} else {
			_ = c.writeFrame(Frame{SessionID: frame.SessionID, Status: StatusEnd, Option: OptionError})
		}
	}
	return nil
}

func (c *serverCarrier) publishReserved(id uint16, session serverSession) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if reserved, exists := c.sessions[id]; exists && reserved == nil && !c.closed {
		c.sessions[id] = session
		return true
	}
	return false
}

func (c *serverCarrier) removeReserved(id uint16) {
	c.mu.Lock()
	if session, exists := c.sessions[id]; exists && session == nil {
		delete(c.sessions, id)
	}
	c.mu.Unlock()
}

func (c *serverCarrier) removeSession(id uint16, expected serverSession) {
	c.mu.Lock()
	if c.sessions[id] == expected {
		delete(c.sessions, id)
	}
	c.mu.Unlock()
}

func (c *serverCarrier) writeFrame(frame Frame) error {
	c.writeMu.Lock()
	encoded, err := encodeFrame(c.writeBuffer, frame)
	if err == nil {
		c.writeBuffer = encoded[:0]
		c.mu.Lock()
		closed := c.closed
		closeErr := c.closeErr
		c.mu.Unlock()
		if closed {
			if closeErr == nil {
				closeErr = net.ErrClosed
			}
			err = closeErr
		} else {
			err = writeFull(c.conn, encoded)
		}
	}
	c.writeMu.Unlock()
	if err != nil {
		// Session close may write an End frame while carrier close is already
		// fanning out. Defer the error close so sync.Once is never re-entered.
		go c.closeWithError(err)
	}
	return err
}

func (c *serverCarrier) closeWithError(cause error) {
	c.closeOnce.Do(func() {
		if cause == nil {
			cause = net.ErrClosed
		}
		c.mu.Lock()
		c.closed = true
		c.closeErr = cause
		sessions := make([]serverSession, 0, len(c.sessions))
		for _, session := range c.sessions {
			if session != nil {
				sessions = append(sessions, session)
			}
		}
		c.sessions = nil
		c.mu.Unlock()

		c.cancel(cause)
		_ = c.conn.Close()
		for _, session := range sessions {
			session.finish(cause, false)
		}
	})
}

func socksaddrFromFrame(frame Frame) M.Socksaddr {
	if frame.DestinationIP.IsValid() {
		return M.Socksaddr{Addr: frame.DestinationIP.Unmap(), Port: frame.Port}
	}
	if address, err := netip.ParseAddr(frame.Destination); err == nil && address.Zone() == "" {
		return M.Socksaddr{Addr: address.Unmap(), Port: frame.Port}
	}
	return M.Socksaddr{Fqdn: frame.Destination, Port: frame.Port}
}

func frameTarget(destination M.Socksaddr) (string, netip.Addr, uint16) {
	if destination.Addr.IsValid() {
		return "", destination.Addr.Unmap(), destination.Port
	}
	return destination.Fqdn, netip.Addr{}, destination.Port
}

func remoteFrameError(frame Frame) error {
	if frame.Option&OptionError != 0 {
		return errors.New("mux.cool remote session error")
	}
	return io.EOF
}
