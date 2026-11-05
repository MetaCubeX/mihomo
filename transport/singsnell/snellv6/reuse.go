package snellv6

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	snell "github.com/metacubex/mihomo/transport/singsnell"
	"github.com/metacubex/mihomo/transport/singsnell/internal/reuse"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

const (
	remoteEOFCode    = reuse.RemoteEOFCode
	remoteEOFMessage = reuse.RemoteEOFMessage
)

func (c *Client) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if c.reuse {
		session, err := c.reuseSession(ctx)
		if err != nil {
			return nil, err
		}
		if snell.KeepSessionFromContext(ctx) {
			session.keepOnce.Store(true)
		}
		conn, err := session.DialConn(destination)
		if err != nil {
			session.Close()
			return nil, err
		}
		return conn, nil
	}
	if c.pool.IsClosed() {
		return nil, net.ErrClosed
	}
	if c.dialer == nil {
		return nil, E.New("snell: missing dialer")
	}
	conn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.server)
	if err != nil {
		return nil, err
	}
	// Surge 6.4.4 (10661): -[SNConnectorV4 targetHandshakeData] appends the connector early data to
	// the handshake buffer, so the first record carries both.
	return c.DialEarlyConn(conn, destination), nil
}

func (c *Client) reuseSession(ctx context.Context) (*reuseSession, error) {
	session, found, closed := c.pool.Take()
	if closed {
		return nil, net.ErrClosed
	}
	if c.dialer == nil {
		return nil, E.New("snell: missing dialer")
	}
	if found {
		return session, nil
	}
	conn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.server)
	if err != nil {
		return nil, err
	}
	if c.pool.IsClosed() {
		conn.Close()
		return nil, net.ErrClosed
	}
	session = c.newReuseSession(conn)
	session.state.Store(uint32(reuse.StateActive))
	return session, nil
}

func (c *Client) Reset() {
	if c.reuse {
		c.pool.Reset()
	}
}

func (c *Client) SetKeepIdleConnections(keep bool) {
	c.closeIdle.Store(!keep)
	if !keep {
		c.CloseIdleConnections()
	}
}

func (c *Client) CloseIdleConnections() {
	if c.reuse {
		c.pool.Reset()
	}
}

func (c *Client) Close() error {
	return c.pool.Close()
}

type reuseSession struct {
	net.Conn
	client *Client

	state    atomic.Uint32
	keepOnce atomic.Bool
	reader   reuse.RecordReader
	writer   reuse.RecordWriter
}

func (c *Client) newReuseSession(conn net.Conn) *reuseSession {
	return &reuseSession{Conn: conn, client: c}
}

func (s *reuseSession) ReuseState() *atomic.Uint32 {
	return &s.state
}

func (s *reuseSession) DialConn(destination M.Socksaddr) (net.Conn, error) {
	state := reuse.State(s.state.Load())
	if state == reuse.StateClosed {
		return nil, net.ErrClosed
	}
	if state != reuse.StateActive {
		return nil, E.New("snell: reuse session is busy")
	}

	return &reuseConn{Conn: s.Conn, session: s, destination: destination}, nil
}

func (s *reuseSession) closeIdle() bool {
	return s.client.closeIdle.Load() && !s.keepOnce.Swap(false)
}

func (s *reuseSession) Release(reusable bool) {
	if !reusable || s.closeIdle() {
		s.Close()
		return
	}
	if !s.state.CompareAndSwap(uint32(reuse.StateActive), uint32(reuse.StateReady)) {
		if reuse.State(s.state.Load()) != reuse.StateClosed {
			s.Close()
		}
		return
	}
	s.client.pool.MoveToPool(s, reuse.StateReady, false)
}

func (s *reuseSession) Close() error {
	if reuse.State(s.state.Swap(uint32(reuse.StateClosed))) == reuse.StateClosed {
		return nil
	}
	return s.Conn.Close()
}

func (s *reuseSession) startDrain() {
	if s.closeIdle() {
		s.Close()
		return
	}
	if !s.state.CompareAndSwap(uint32(reuse.StateActive), uint32(reuse.StateWaiting)) {
		if reuse.State(s.state.Load()) != reuse.StateClosed {
			s.Close()
		}
		return
	}
	if !s.client.pool.MoveToPool(s, reuse.StateWaiting, true) {
		return
	}
	go s.drain()
}

func (s *reuseSession) drain() {
	defer s.client.pool.DrainDone()
	var discarded int
	for {
		record, err := s.reader.NextRecord()
		if errors.Is(err, io.EOF) {
			s.state.CompareAndSwap(uint32(reuse.StateWaiting), uint32(reuse.StateReady))
			return
		}
		if err != nil {
			s.Close()
			return
		}
		// Surge 6.7.0 (11520): SNConnectorV4::socket:didReadData: discards data
		// received while waiting for server EOF and closes after 0x80001 bytes.
		discarded += record.Len()
		record.Release()
		if discarded >= reuse.WaitingDiscardLimit {
			s.Close()
			return
		}
	}
}

type reuseConn struct {
	net.Conn
	session     *reuseSession
	destination M.Socksaddr

	access          sync.Mutex
	writer          reuse.RecordWriter
	closeWriteOnce  sync.Once
	closeWriteErr   error
	closeOnce       sync.Once
	closeErr        error
	replyRead       atomic.Bool
	readWaitOptions N.ReadWaitOptions
	closed          atomic.Bool
	readActionCount atomic.Int32
	readClosed      atomic.Bool
}

func (c *reuseConn) readResponse() error {
	if c.replyRead.Load() {
		return nil
	}
	var record *buf.Buffer
	var err error
	if c.session.reader == nil {
		c.session.reader, record, err = readFirstRecord(c.session.Conn, c.session.client.mode, c.session.client.psk, c.session.client.profile, c.readWaitOptions)
	} else {
		record, err = c.session.reader.ReadRecord()
	}
	if err != nil {
		return E.Cause(err, "read reply")
	}
	cached, err := reuse.ParseReply(record)
	if err != nil {
		return err
	}
	c.session.reader.SetCache(cached)
	c.replyRead.Store(true)
	return nil
}

func (c *reuseConn) Read(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.readActionCount.Add(1)
	defer c.readActionCount.Add(-1)
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	err := c.readResponse()
	if err != nil {
		return 0, err
	}
	var discarded int
	for {
		n, err := c.session.reader.Read(p)
		if c.closed.Load() {
			discarded += n
			if errors.Is(err, io.EOF) {
				c.readClosed.Store(true)
				c.session.state.CompareAndSwap(uint32(reuse.StateWaiting), uint32(reuse.StateReady))
				return 0, err
			}
			if err != nil {
				c.session.Close()
				return 0, err
			}
			if discarded >= reuse.WaitingDiscardLimit {
				c.session.Close()
				return 0, E.New("snell: read too much data after client EOF")
			}
			continue
		}
		if errors.Is(err, io.EOF) {
			c.readClosed.Store(true)
		}
		return n, err
	}
}

func (c *reuseConn) ReadBuffer(buffer *buf.Buffer) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	c.readActionCount.Add(1)
	defer c.readActionCount.Add(-1)
	if c.closed.Load() {
		return net.ErrClosed
	}
	err := c.readResponse()
	if err != nil {
		return err
	}
	var discarded int
	for {
		bufferLen := buffer.Len()
		err = c.session.reader.ReadBuffer(buffer)
		if c.closed.Load() {
			discarded += buffer.Len() - bufferLen
			buffer.Truncate(bufferLen)
			if errors.Is(err, io.EOF) {
				c.readClosed.Store(true)
				c.session.state.CompareAndSwap(uint32(reuse.StateWaiting), uint32(reuse.StateReady))
				return err
			}
			if err != nil {
				c.session.Close()
				return err
			}
			if discarded >= reuse.WaitingDiscardLimit {
				c.session.Close()
				return E.New("snell: read too much data after client EOF")
			}
			continue
		}
		if errors.Is(err, io.EOF) {
			c.readClosed.Store(true)
		}
		return err
	}
}

func (c *reuseConn) writeRequest(payload []byte) error {
	requestPayload := snell.Request{Command: snell.CommandConnectV2, ClientID: c.session.client.userKey, Destination: c.destination}
	request := buf.NewSize(requestPayload.Len() + len(payload))
	err := requestPayload.Write(request)
	if err != nil {
		request.Release()
		return err
	}
	if len(payload) > 0 {
		common.Must1(request.Write(payload))
	}
	defer request.Release()

	data := request.Bytes()
	if c.session.writer == nil {
		first := data
		if len(first) > maxPayload {
			first = data[:maxPayload]
		}
		c.session.writer, err = writeFirstRecord(c.session.Conn, c.session.client.mode, c.session.client.psk, c.session.client.profile, first)
		if err != nil {
			c.session.Release(false)
			return E.Cause(err, "write request")
		}
		data = data[len(first):]
	}
	if len(data) > 0 {
		_, err = c.session.writer.Write(data)
		if err != nil {
			c.session.Release(false)
			return E.Cause(err, "write request")
		}
	}
	c.writer = c.session.writer
	return nil
}

func (c *reuseConn) writeRequestBuffer(buffer *buf.Buffer) error {
	requestPayload := snell.Request{Command: snell.CommandConnectV2, ClientID: c.session.client.userKey, Destination: c.destination}
	request := buf.With(buffer.ExtendHeader(requestPayload.Len()))
	err := requestPayload.Write(request)
	if err != nil {
		buffer.Release()
		return err
	}
	if c.session.writer == nil {
		c.session.writer, err = writeFirstRecordBuffer(c.session.Conn, c.session.client.mode, c.session.client.psk, c.session.client.profile, buffer)
	} else {
		err = c.session.writer.WriteBuffer(buffer)
	}
	if err != nil {
		c.session.Release(false)
		return E.Cause(err, "write request")
	}
	c.writer = c.session.writer
	return nil
}

func (c *reuseConn) Write(p []byte) (int, error) {
	if c.writer != nil {
		return c.writer.Write(p)
	}
	c.access.Lock()
	if c.writer != nil {
		c.access.Unlock()
		return c.writer.Write(p)
	}
	defer c.access.Unlock()
	err := c.writeRequest(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *reuseConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.writer != nil {
		return c.writer.WriteBuffer(buffer)
	}
	c.access.Lock()
	if c.writer != nil {
		c.access.Unlock()
		return c.writer.WriteBuffer(buffer)
	}
	defer c.access.Unlock()
	return c.writeRequestBuffer(buffer)
}

func (c *reuseConn) CreateVectorisedWriter() (N.VectorisedWriter, bool) {
	upstreamWriter, created := bufio.CreateVectorisedWriter(c.session.Conn)
	if !created {
		return nil, false
	}
	return &reuseVectorisedWriter{conn: c, upstream: upstreamWriter}, true
}

type reuseVectorisedWriter struct {
	conn     *reuseConn
	upstream N.VectorisedWriter
}

func (w *reuseVectorisedWriter) WriteVectorised(buffers []*buf.Buffer) error {
	conn := w.conn
	if conn.writer != nil {
		return conn.writer.CreateVectorisedWriterFor(w.upstream).WriteVectorised(buffers)
	}
	conn.access.Lock()
	defer conn.access.Unlock()
	if conn.writer != nil {
		return conn.writer.CreateVectorisedWriterFor(w.upstream).WriteVectorised(buffers)
	}
	for index, buffer := range buffers {
		if buffer.IsEmpty() {
			buffer.Release()
			continue
		}
		err := conn.writeRequestBuffer(buffer)
		if err != nil {
			buf.ReleaseMulti(buffers[index+1:])
			return err
		}
		if index+1 < len(buffers) {
			return conn.writer.CreateVectorisedWriterFor(w.upstream).WriteVectorised(buffers[index+1:])
		}
		return nil
	}
	return nil
}

func (c *reuseConn) CloseWrite() error {
	c.closeWriteOnce.Do(func() {
		c.access.Lock()
		defer c.access.Unlock()
		if c.writer == nil {
			c.closeWriteErr = c.writeRequest(nil)
			if c.closeWriteErr != nil {
				return
			}
		}
		c.closeWriteErr = c.writer.WriteZeroChunk()
	})
	return c.closeWriteErr
}

func (c *reuseConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		if !c.replyRead.Load() {
			c.session.Release(false)
			return
		}
		c.closeErr = c.CloseWrite()
		if c.closeErr != nil {
			c.session.Release(false)
			return
		}
		c.session.Conn.SetReadDeadline(time.Time{})
		c.session.Conn.SetWriteDeadline(time.Time{})
		if c.readClosed.Load() {
			c.session.Release(true)
			return
		}
		if c.session.closeIdle() {
			c.session.Close()
			return
		}
		// Surge 6.7.0 (11520): SNConnectorV4::readServerEOFIfNotInReadState: starts waiting-state EOF
		// reads when _socketReadActionCounter is 0.
		if c.readActionCount.Load() > 0 {
			if !c.session.state.CompareAndSwap(uint32(reuse.StateActive), uint32(reuse.StateWaiting)) {
				if reuse.State(c.session.state.Load()) != reuse.StateClosed {
					c.session.Close()
				}
				return
			}
			poolState := reuse.StateWaiting
			if c.readClosed.Load() {
				c.session.state.CompareAndSwap(uint32(reuse.StateWaiting), uint32(reuse.StateReady))
				poolState = reuse.StateReady
			}
			if !c.session.client.pool.MoveToPool(c.session, poolState, false) {
				return
			}
			return
		}
		c.session.startDrain()
	})
	return c.closeErr
}

func (c *reuseConn) CreateReadWaiter() (N.ReadWaiter, bool) {
	return &reuseReadWaiter{conn: c}, true
}

type reuseReadWaiter struct {
	conn *reuseConn
}

func (w *reuseReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	w.conn.readWaitOptions = options
	if w.conn.session.reader != nil {
		w.conn.session.reader.InitializeReadWaiter(options)
	}
	return false
}

func (w *reuseReadWaiter) WaitReadBuffer() (*buf.Buffer, error) {
	if w.conn.closed.Load() {
		return nil, net.ErrClosed
	}
	w.conn.readActionCount.Add(1)
	defer w.conn.readActionCount.Add(-1)
	if w.conn.closed.Load() {
		return nil, net.ErrClosed
	}
	err := w.conn.readResponse()
	if err != nil {
		return nil, err
	}
	var discarded int
	for {
		buffer, err := w.conn.session.reader.WaitReadBuffer()
		if w.conn.closed.Load() {
			if buffer != nil {
				discarded += buffer.Len()
				buffer.Release()
			}
			if errors.Is(err, io.EOF) {
				w.conn.readClosed.Store(true)
				w.conn.session.state.CompareAndSwap(uint32(reuse.StateWaiting), uint32(reuse.StateReady))
				return nil, err
			}
			if err != nil {
				w.conn.session.Close()
				return nil, err
			}
			if discarded >= reuse.WaitingDiscardLimit {
				w.conn.session.Close()
				return nil, E.New("snell: read too much data after client EOF")
			}
			continue
		}
		if errors.Is(err, io.EOF) {
			w.conn.readClosed.Store(true)
		}
		return buffer, err
	}
}

func (c *reuseConn) FrontHeadroom() int {
	if c.writer != nil {
		return c.writer.FrontHeadroom()
	}
	requestPayload := snell.Request{Command: snell.CommandConnectV2, ClientID: c.session.client.userKey, Destination: c.destination}
	switch c.session.client.mode {
	case ModeUnsafeRaw:
		return requestPayload.Len() + snell.HeaderPlainLen
	case ModeUnshaped:
		return requestPayload.Len() + snell.SaltLen + snell.HeaderCipherLen
	default:
		return requestPayload.Len() + c.session.client.profile.saltBlockLen + c.session.client.profile.recordPrefixMax + snell.HeaderCipherLen + c.session.client.profile.padMaxHeadroom
	}
}

func (c *reuseConn) RearHeadroom() int {
	if c.writer != nil {
		return c.writer.RearHeadroom()
	}
	if c.session.client.mode == ModeUnsafeRaw {
		return 0
	}
	return snell.AEADTagLen
}

func (c *reuseConn) WriterMTU() int {
	if c.writer != nil {
		return c.writer.WriterMTU()
	}
	if c.session.client.mode == ModeDefault {
		return c.session.client.profile.chunkMax
	}
	return maxPayload
}

func (c *reuseConn) NeedHandshakeForRead() bool {
	return !c.replyRead.Load()
}

func (c *reuseConn) NeedHandshakeForWrite() bool {
	return c.writer == nil
}

func (c *reuseConn) NeedAdditionalReadDeadline() bool {
	return !c.replyRead.Load()
}

func (c *reuseConn) Upstream() any {
	return c.session.Conn
}

func (c *reuseConn) RemoteAddr() net.Addr {
	return c.destination.TCPAddr()
}

type serverReuseSession[U comparable] struct {
	net.Conn
	service      *Service
	multiService *MultiService[U]
	reader       reuse.RecordReader
	writer       reuse.RecordWriter
}

func (s *serverReuseSession[U]) Serve(ctx context.Context, source M.Socksaddr, onClose snell.CloseHandlerFunc, record *buf.Buffer, request snell.Request) (err error) {
	callOnClose := true
	if onClose != nil {
		defer func() {
			if callOnClose {
				onClose(err)
			}
		}()
	}
	for {
		requestCtx := ctx
		if s.multiService != nil && request.Command != snell.CommandPing {
			requestCtx, err = s.multiService.authenticate(ctx, request)
			if err != nil {
				record.Release()
				s.Conn.Close()
				return err
			}
		}
		switch request.Command {
		case snell.CommandConnect, snell.CommandConnectV2:
		case snell.CommandUDP:
			// snell-server v6.0.0b4: FUN_00141bc0 rejects UDP tunnel requests when the
			// first UDP datagram starts in the same decrypted frame as the tunnel request.
			if !record.IsEmpty() {
				record.Release()
				s.Conn.Close()
				return errInvalidUDPTunnelRequest
			}
			record.Release()
			packetConn := &serverPacketConn{Conn: s.Conn, service: s.service, reader: s.reader, writer: s.writer}
			err = s.service.newPacketConnection(requestCtx, packetConn, source, onClose)
			if err != nil {
				s.Conn.Close()
				return err
			}
			s.writer = packetConn.writer
			callOnClose = false
			return nil
		case snell.CommandPing:
			record.Release()
			pong := [1]byte{snell.ReplyPong}
			if s.writer == nil {
				s.writer, err = writeFirstRecord(s.Conn, s.service.mode, s.service.psk, s.service.profile, pong[:])
			} else {
				_, err = s.writer.Write(pong[:])
			}
			if err != nil {
				s.Conn.Close()
				return err
			}
			s.Conn.Close()
			return nil
		default:
			record.Release()
			s.Conn.Close()
			return E.Extend(snell.ErrUnsupportedCommand, request.Command)
		}
		serverConn := &serverReuseConn[U]{Conn: s.Conn, session: s, completion: make(chan struct{})}
		if record.IsEmpty() {
			record.Release()
		} else {
			s.reader.SetCache(record)
		}
		s.service.handler.NewConnectionEx(requestCtx, serverConn, source, request.Destination, serverConn.completeLogicalConnection)
		select {
		case <-serverConn.completion:
		case <-requestCtx.Done():
			s.Conn.Close()
			return requestCtx.Err()
		}
		err = serverConn.CloseWrite()
		if err != nil {
			s.Conn.Close()
			return err
		}
		if serverConn.aborted.Load() {
			return nil
		}
		if !serverConn.readClosed.Load() {
			// snell-server v6.0.0b4: after writing the EOF packet, FUN_00141bc0 keeps
			// consuming client records (forwarding them into the still writable
			// outgoing socket) until the zero chunk reaches FUN_001419e0 ->
			// FUN_001402c0 -> FUN_001401b0, which resets the tunnel stage so the
			// next record is parsed as a request. The handler has already released
			// the upstream, so discard instead, capped like the client waiting state.
			var discarded int
			for {
				var drainRecord *buf.Buffer
				drainRecord, err = s.reader.NextRecord()
				if err != nil {
					break
				}
				discarded += drainRecord.Len()
				drainRecord.Release()
				if discarded >= reuse.WaitingDiscardLimit {
					s.Conn.Close()
					return E.New("snell: read too much data after request end")
				}
			}
			if !errors.Is(err, io.EOF) {
				s.Conn.Close()
				return E.Cause(err, "drain request")
			}
		}
		record, err = s.reader.ReadRecord()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			s.Conn.Close()
			return E.Cause(err, "read request")
		}
		request, err = s.service.readRequest(record)
		if err != nil {
			record.Release()
			s.Conn.Close()
			return E.Cause(err, "decode request")
		}
	}
}

type serverReuseConn[U comparable] struct {
	net.Conn
	session *serverReuseSession[U]

	access         sync.Mutex
	closeWriteOnce sync.Once
	closeWriteErr  error
	closeOnce      sync.Once
	closeErr       error
	readClosed     atomic.Bool
	aborted        atomic.Bool
	replyWritten   bool
	writeClosed    bool
	completeOnce   sync.Once
	completion     chan struct{}
}

func (c *serverReuseConn[U]) writeResponse(payload []byte) error {
	first := payload
	if len(first) > maxPayload-1 {
		first = payload[:maxPayload-1]
	}
	reply := make([]byte, 1+len(first))
	reply[0] = snell.ReplyTunnel
	copy(reply[1:], first)
	var err error
	if c.session.writer == nil {
		c.session.writer, err = writeFirstRecord(c.session.Conn, c.session.service.mode, c.session.service.psk, c.session.service.profile, reply)
	} else {
		_, err = c.session.writer.Write(reply)
	}
	if err != nil {
		return E.Cause(err, "write reply")
	}
	c.replyWritten = true
	if len(payload) > len(first) {
		_, err = c.session.writer.Write(payload[len(first):])
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *serverReuseConn[U]) writeResponseBuffer(buffer *buf.Buffer) error {
	if c.session.writer != nil {
		buffer.ExtendHeader(1)[0] = snell.ReplyTunnel
		err := c.session.writer.WriteBuffer(buffer)
		if err != nil {
			return E.Cause(err, "write reply")
		}
		c.replyWritten = true
		return nil
	}
	buffer.ExtendHeader(1)[0] = snell.ReplyTunnel
	writer, err := writeFirstRecordBuffer(c.session.Conn, c.session.service.mode, c.session.service.psk, c.session.service.profile, buffer)
	if err != nil {
		return E.Cause(err, "write reply")
	}
	c.session.writer = writer
	c.replyWritten = true
	return nil
}

func (c *serverReuseConn[U]) writeErrorResponse() error {
	message := []byte(remoteEOFMessage)
	reply := make([]byte, 3+len(message))
	reply[0] = snell.ReplyError
	reply[1] = remoteEOFCode
	reply[2] = byte(len(message))
	copy(reply[3:], message)
	var err error
	if c.session.writer == nil {
		c.session.writer, err = writeFirstRecord(c.session.Conn, c.session.service.mode, c.session.service.psk, c.session.service.profile, reply)
	} else {
		_, err = c.session.writer.Write(reply)
	}
	if err != nil {
		return E.Cause(err, "write error reply")
	}
	return nil
}

func (c *serverReuseConn[U]) Read(p []byte) (int, error) {
	n, err := c.session.reader.Read(p)
	if errors.Is(err, io.EOF) {
		c.readClosed.Store(true)
	}
	return n, err
}

func (c *serverReuseConn[U]) ReadBuffer(buffer *buf.Buffer) error {
	err := c.session.reader.ReadBuffer(buffer)
	if errors.Is(err, io.EOF) {
		c.readClosed.Store(true)
	}
	return err
}

func (c *serverReuseConn[U]) Write(p []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.writeClosed {
		return 0, net.ErrClosed
	}
	if c.replyWritten {
		return c.session.writer.Write(p)
	}
	err := c.writeResponse(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *serverReuseConn[U]) WriteBuffer(buffer *buf.Buffer) error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.writeClosed {
		buffer.Release()
		return net.ErrClosed
	}
	if c.replyWritten {
		return c.session.writer.WriteBuffer(buffer)
	}
	return c.writeResponseBuffer(buffer)
}

func (c *serverReuseConn[U]) CreateVectorisedWriter() (N.VectorisedWriter, bool) {
	upstreamWriter, created := bufio.CreateVectorisedWriter(c.session.Conn)
	if !created {
		return nil, false
	}
	return &serverReuseVectorisedWriter[U]{conn: c, upstream: upstreamWriter}, true
}

type serverReuseVectorisedWriter[U comparable] struct {
	conn     *serverReuseConn[U]
	upstream N.VectorisedWriter
}

func (w *serverReuseVectorisedWriter[U]) WriteVectorised(buffers []*buf.Buffer) error {
	conn := w.conn
	conn.access.Lock()
	defer conn.access.Unlock()
	if conn.writeClosed {
		buf.ReleaseMulti(buffers)
		return net.ErrClosed
	}
	if conn.replyWritten {
		return conn.session.writer.CreateVectorisedWriterFor(w.upstream).WriteVectorised(buffers)
	}
	for index, buffer := range buffers {
		if buffer.IsEmpty() {
			buffer.Release()
			continue
		}
		err := conn.writeResponseBuffer(buffer)
		if err != nil {
			buf.ReleaseMulti(buffers[index+1:])
			return err
		}
		if index+1 < len(buffers) {
			return conn.session.writer.CreateVectorisedWriterFor(w.upstream).WriteVectorised(buffers[index+1:])
		}
		return nil
	}
	return nil
}

func (c *serverReuseConn[U]) CloseWrite() error {
	c.closeWriteOnce.Do(func() {
		c.access.Lock()
		defer c.access.Unlock()
		c.writeClosed = true
		// snell-server v6.0.0b4: FUN_001414e0 -> FUN_00140390 reports upstream EOF
		// before any payload as ReplyError 0x65 "Remote EOF", marks the context
		// aborted, and FUN_00141390 closes the tunnel after the error data is written.
		if !c.replyWritten {
			c.closeWriteErr = c.writeErrorResponse()
			if c.closeWriteErr == nil {
				c.aborted.Store(true)
				c.closeWriteErr = c.session.Conn.Close()
			}
			return
		}
		c.closeWriteErr = c.session.writer.WriteZeroChunk()
	})
	return c.closeWriteErr
}

func (c *serverReuseConn[U]) Close() error {
	c.closeOnce.Do(func() {
		// The handler may close this side while its peer copy is still reading.
		// onClose owns completion and runs only after both copy directions exit.
		c.closeErr = c.CloseWrite()
	})
	return c.closeErr
}

func (c *serverReuseConn[U]) completeLogicalConnection(error) {
	c.completeOnce.Do(func() {
		close(c.completion)
	})
}

func (c *serverReuseConn[U]) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	return c.session.reader.InitializeReadWaiter(options)
}

func (c *serverReuseConn[U]) WaitReadBuffer() (*buf.Buffer, error) {
	buffer, err := c.session.reader.WaitReadBuffer()
	if errors.Is(err, io.EOF) {
		c.readClosed.Store(true)
	}
	return buffer, err
}

func (c *serverReuseConn[U]) FrontHeadroom() int {
	if c.replyWritten {
		return c.session.writer.FrontHeadroom()
	}
	if c.session.writer != nil {
		return 1 + c.session.writer.FrontHeadroom()
	}
	switch c.session.service.mode {
	case ModeUnsafeRaw:
		return 1 + snell.HeaderPlainLen
	case ModeUnshaped:
		return 1 + snell.SaltLen + snell.HeaderCipherLen
	default:
		return 1 + c.session.service.profile.saltBlockLen + c.session.service.profile.recordPrefixMax + snell.HeaderCipherLen + c.session.service.profile.padMaxHeadroom
	}
}

func (c *serverReuseConn[U]) RearHeadroom() int {
	if c.session.writer != nil {
		return c.session.writer.RearHeadroom()
	}
	if c.session.service.mode == ModeUnsafeRaw {
		return 0
	}
	return snell.AEADTagLen
}

func (c *serverReuseConn[U]) WriterMTU() int {
	if c.session.writer != nil {
		return c.session.writer.WriterMTU()
	}
	if c.session.service.mode == ModeDefault {
		return c.session.service.profile.chunkMax
	}
	return maxPayload
}

func (c *serverReuseConn[U]) Upstream() any {
	return c.session.Conn
}

var (
	_ N.ExtendedConn               = (*reuseConn)(nil)
	_ N.ReadWaitCreator            = (*reuseConn)(nil)
	_ snell.VectorisedWriteCreator = (*reuseConn)(nil)
	_ snell.EarlyReader            = (*reuseConn)(nil)
	_ snell.EarlyWriter            = (*reuseConn)(nil)
	_ N.WriteCloser                = (*reuseConn)(nil)
	_ N.VectorisedWriter           = (*reuseVectorisedWriter)(nil)
	_ N.ReadWaiter                 = (*reuseReadWaiter)(nil)
	_ N.ExtendedConn               = (*serverReuseConn[struct{}])(nil)
	_ N.ReadWaiter                 = (*serverReuseConn[struct{}])(nil)
	_ snell.VectorisedWriteCreator = (*serverReuseConn[struct{}])(nil)
	_ N.VectorisedWriter           = (*serverReuseVectorisedWriter[struct{}])(nil)
	_ N.WriteCloser                = (*serverReuseConn[struct{}])(nil)
)
