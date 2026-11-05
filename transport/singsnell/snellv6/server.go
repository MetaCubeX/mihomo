package snellv6

import (
	"context"
	"io"
	"net"
	"sync"

	snell "github.com/metacubex/mihomo/transport/singsnell"
	"github.com/metacubex/mihomo/transport/singsnell/internal/reuse"
	"github.com/metacubex/sing/common/auth"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type Service struct {
	psk     []byte
	mode    Mode
	profile *Profile
	handler snell.Handler
}

type ServerOptions struct {
	PSK     []byte
	Mode    Mode
	Handler snell.Handler
}

func NewService(options ServerOptions) (*Service, error) {
	if len(options.PSK) == 0 {
		return nil, snell.ErrMissingPSK
	}
	// snell-server v6.0.0b4: FUN_00138120: rejects PSKs outside the 12..255-byte range.
	if len(options.PSK) < 12 || len(options.PSK) > 255 {
		return nil, E.New("snell: psk length must be between 12 and 255 bytes")
	}
	if options.Mode != ModeDefault && options.Mode != ModeUnshaped && options.Mode != ModeUnsafeRaw {
		return nil, E.New("snell: unknown v6 mode: ", int(options.Mode))
	}
	service := &Service{psk: options.PSK, mode: options.Mode, handler: options.Handler}
	if options.Mode == ModeDefault {
		service.profile = NewProfile(options.PSK)
	}
	return service, nil
}

func (s *Service) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose snell.CloseHandlerFunc) error {
	err := s.newConnection(ctx, conn, source, onClose)
	if err != nil {
		return &snell.ServerError{Conn: conn, Source: source, Cause: err}
	}
	return nil
}

type MultiService[U comparable] struct {
	*Service
	users map[string]U
}

var errInvalidUDPTunnelRequest = E.New("snell: invalid udp tunnel request")

func NewMultiService[U comparable](options ServerOptions) (*MultiService[U], error) {
	service, err := NewService(options)
	if err != nil {
		return nil, err
	}
	return &MultiService[U]{Service: service, users: make(map[string]U)}, nil
}

func (s *MultiService[U]) UpdateUsers(users []U, userKeys [][]byte) error {
	if len(users) != len(userKeys) {
		return E.New("snell: user/key count mismatch")
	}
	if len(users) == 0 {
		return snell.ErrNoUsers
	}
	userMap := make(map[string]U, len(users))
	for index, user := range users {
		key := userKeys[index]
		if len(key) == 0 {
			return snell.ErrBadUserKey
		}
		if len(key) > 255 {
			return E.New("snell: user key too long")
		}
		keyString := string(key)
		if _, loaded := userMap[keyString]; loaded {
			return snell.ErrDuplicateUserKey
		}
		userMap[keyString] = user
	}
	s.users = userMap
	return nil
}

func (s *MultiService[U]) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose snell.CloseHandlerFunc) error {
	err := s.newConnection(ctx, conn, source, onClose)
	if err != nil {
		return &snell.ServerError{Conn: conn, Source: source, Cause: err}
	}
	return nil
}

func (s *MultiService[U]) authenticate(ctx context.Context, request snell.Request) (context.Context, error) {
	user, loaded := s.users[string(request.ClientID)]
	if !loaded {
		return nil, snell.ErrBadUserKey
	}
	return auth.ContextWithUser(ctx, user), nil
}

func (s *Service) readRequest(record *buf.Buffer) (snell.Request, error) {
	prefix := make([]byte, 3)
	_, err := io.ReadFull(record, prefix)
	if err != nil {
		return snell.Request{}, err
	}
	if prefix[0] != snell.RequestVersion {
		return snell.Request{}, E.Extend(snell.ErrBadVersion, "request version ", prefix[0])
	}
	request := snell.Request{Command: prefix[1]}
	// snell-server v6.0.0b4: FUN_00141bc0 handles SN_COMMAND_PING immediately after
	// the version/command bytes and aborts with PONG data, without consuming client-id bytes.
	if request.Command == snell.CommandPing {
		return request, nil
	}
	clientIDLen := int(prefix[2])
	if clientIDLen > 0 {
		request.ClientID = make([]byte, clientIDLen)
		_, err = io.ReadFull(record, request.ClientID)
		if err != nil {
			return snell.Request{}, err
		}
	}
	switch request.Command {
	case snell.CommandConnect, snell.CommandConnectV2:
		request.Destination, err = snell.ReadConnectAddress(record)
		if err != nil {
			return snell.Request{}, err
		}
	case snell.CommandUDP:
	default:
		return snell.Request{}, E.Extend(snell.ErrUnsupportedCommand, request.Command)
	}
	return request, nil
}

func (s *Service) newConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose snell.CloseHandlerFunc) error {
	reader, record, err := readFirstRecord(conn, s.mode, s.psk, s.profile, N.ReadWaitOptions{})
	if err != nil {
		return E.Cause(err, "read request")
	}
	request, err := s.readRequest(record)
	if err != nil {
		record.Release()
		return E.Cause(err, "decode request")
	}

	switch request.Command {
	case snell.CommandConnect:
		serverConn := &serverConn{Conn: conn, service: s, reader: reader}
		if record.IsEmpty() {
			record.Release()
		} else {
			reader.SetCache(record)
		}
		s.handler.NewConnectionEx(ctx, serverConn, source, request.Destination, onClose)
		return nil
	case snell.CommandConnectV2:
		reuseSession := &serverReuseSession[struct{}]{Conn: conn, service: s, reader: reader}
		return reuseSession.Serve(ctx, source, onClose, record, request)
	case snell.CommandUDP:
		// snell-server v6.0.0b4: FUN_00141bc0 rejects UDP tunnel requests when the
		// first UDP datagram starts in the same decrypted frame as the tunnel request.
		if !record.IsEmpty() {
			record.Release()
			conn.Close()
			return errInvalidUDPTunnelRequest
		}
		record.Release()
		return s.newPacketConnection(ctx, &serverPacketConn{Conn: conn, service: s, reader: reader}, source, onClose)
	case snell.CommandPing:
		record.Release()
		pong := [1]byte{snell.ReplyPong}
		_, err = writeFirstRecord(conn, s.mode, s.psk, s.profile, pong[:])
		closeErr := conn.Close()
		if err != nil {
			return err
		}
		return closeErr
	default:
		record.Release()
		return E.Extend(snell.ErrUnsupportedCommand, request.Command)
	}
}

func (s *Service) newPacketConnection(ctx context.Context, packetConn *serverPacketConn, source M.Socksaddr, onClose snell.CloseHandlerFunc) error {
	err := packetConn.writeTunnelReply()
	if err != nil {
		return err
	}
	firstPacket := buf.NewPacket()
	destination, err := packetConn.ReadPacket(firstPacket)
	if err != nil {
		firstPacket.Release()
		return E.Cause(err, "read first packet")
	}
	s.handler.NewPacketConnectionEx(ctx, bufio.NewCachedPacketConn(packetConn, firstPacket, destination), source, destination, onClose)
	return nil
}

func (s *MultiService[U]) newConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose snell.CloseHandlerFunc) error {
	reader, record, err := readFirstRecord(conn, s.mode, s.psk, s.profile, N.ReadWaitOptions{})
	if err != nil {
		return E.Cause(err, "read request")
	}
	request, err := s.readRequest(record)
	if err != nil {
		record.Release()
		return E.Cause(err, "decode request")
	}

	switch request.Command {
	case snell.CommandConnect:
		requestCtx, err := s.authenticate(ctx, request)
		if err != nil {
			record.Release()
			return err
		}
		serverConn := &serverConn{Conn: conn, service: s.Service, reader: reader}
		if record.IsEmpty() {
			record.Release()
		} else {
			reader.SetCache(record)
		}
		s.handler.NewConnectionEx(requestCtx, serverConn, source, request.Destination, onClose)
		return nil
	case snell.CommandConnectV2:
		reuseSession := &serverReuseSession[U]{Conn: conn, service: s.Service, multiService: s, reader: reader}
		return reuseSession.Serve(ctx, source, onClose, record, request)
	case snell.CommandUDP:
		requestCtx, err := s.authenticate(ctx, request)
		if err != nil {
			record.Release()
			return err
		}
		// snell-server v6.0.0b4: FUN_00141bc0 rejects UDP tunnel requests when the
		// first UDP datagram starts in the same decrypted frame as the tunnel request.
		if !record.IsEmpty() {
			record.Release()
			conn.Close()
			return errInvalidUDPTunnelRequest
		}
		record.Release()
		return s.newPacketConnection(requestCtx, &serverPacketConn{Conn: conn, service: s.Service, reader: reader}, source, onClose)
	case snell.CommandPing:
		record.Release()
		pong := [1]byte{snell.ReplyPong}
		_, err = writeFirstRecord(conn, s.mode, s.psk, s.profile, pong[:])
		closeErr := conn.Close()
		if err != nil {
			return err
		}
		return closeErr
	default:
		record.Release()
		return E.Extend(snell.ErrUnsupportedCommand, request.Command)
	}
}

var (
	_ snell.Service = (*Service)(nil)
	_ snell.Service = (*MultiService[int])(nil)
)

type serverConn struct {
	net.Conn
	service *Service
	reader  reuse.RecordReader

	access sync.Mutex
	writer reuse.RecordWriter

	closeWriteOnce sync.Once
	closeWriteErr  error
}

func (c *serverConn) writeResponse(payload []byte) error {
	first := payload
	if len(first) > maxPayload-1 {
		first = payload[:maxPayload-1]
	}
	reply := make([]byte, 1+len(first))
	reply[0] = snell.ReplyTunnel
	copy(reply[1:], first)
	writer, err := writeFirstRecord(c.Conn, c.service.mode, c.service.psk, c.service.profile, reply)
	if err != nil {
		return E.Cause(err, "write reply")
	}
	c.writer = writer
	if len(payload) > len(first) {
		_, err = writer.Write(payload[len(first):])
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *serverConn) writeResponseBuffer(buffer *buf.Buffer) error {
	buffer.ExtendHeader(1)[0] = snell.ReplyTunnel
	writer, err := writeFirstRecordBuffer(c.Conn, c.service.mode, c.service.psk, c.service.profile, buffer)
	if err != nil {
		return E.Cause(err, "write reply")
	}
	c.writer = writer
	return nil
}

func (c *serverConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *serverConn) ReadBuffer(buffer *buf.Buffer) error {
	return c.reader.ReadBuffer(buffer)
}

func (c *serverConn) Write(p []byte) (int, error) {
	c.access.Lock()
	if c.writer != nil {
		writer := c.writer
		c.access.Unlock()
		return writer.Write(p)
	}
	defer c.access.Unlock()
	err := c.writeResponse(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *serverConn) WriteBuffer(buffer *buf.Buffer) error {
	c.access.Lock()
	if c.writer != nil {
		writer := c.writer
		c.access.Unlock()
		return writer.WriteBuffer(buffer)
	}
	defer c.access.Unlock()
	return c.writeResponseBuffer(buffer)
}

func (c *serverConn) CreateVectorisedWriter() (N.VectorisedWriter, bool) {
	upstreamWriter, created := bufio.CreateVectorisedWriter(c.Conn)
	if !created {
		return nil, false
	}
	return &serverVectorisedWriter{conn: c, upstream: upstreamWriter}, true
}

type serverVectorisedWriter struct {
	conn     *serverConn
	upstream N.VectorisedWriter
}

func (w *serverVectorisedWriter) WriteVectorised(buffers []*buf.Buffer) error {
	conn := w.conn
	conn.access.Lock()
	if conn.writer != nil {
		recordWriter := conn.writer
		conn.access.Unlock()
		return recordWriter.CreateVectorisedWriterFor(w.upstream).WriteVectorised(buffers)
	}
	for index, buffer := range buffers {
		if buffer.IsEmpty() {
			buffer.Release()
			continue
		}
		err := conn.writeResponseBuffer(buffer)
		if err != nil {
			conn.access.Unlock()
			buf.ReleaseMulti(buffers[index+1:])
			return err
		}
		if index+1 < len(buffers) {
			recordWriter := conn.writer
			conn.access.Unlock()
			return recordWriter.CreateVectorisedWriterFor(w.upstream).WriteVectorised(buffers[index+1:])
		}
		conn.access.Unlock()
		return nil
	}
	conn.access.Unlock()
	return nil
}

func (c *serverConn) CloseWrite() error {
	c.closeWriteOnce.Do(func() {
		c.access.Lock()
		defer c.access.Unlock()
		// snell-server v6.0.0b4 closes non-reusable command-1 tunnels on upstream EOF instead of writing a Snell zero chunk.
		c.closeWriteErr = c.Conn.Close()
	})
	return c.closeWriteErr
}

func (c *serverConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	return c.reader.InitializeReadWaiter(options)
}

func (c *serverConn) WaitReadBuffer() (*buf.Buffer, error) {
	return c.reader.WaitReadBuffer()
}

func (c *serverConn) FrontHeadroom() int {
	if c.writer != nil {
		return c.writer.FrontHeadroom()
	}
	switch c.service.mode {
	case ModeUnsafeRaw:
		return 1 + snell.HeaderPlainLen
	case ModeUnshaped:
		return 1 + snell.SaltLen + snell.HeaderCipherLen
	default:
		return 1 + c.service.profile.saltBlockLen + c.service.profile.recordPrefixMax + snell.HeaderCipherLen + c.service.profile.padMaxHeadroom
	}
}

func (c *serverConn) RearHeadroom() int {
	if c.writer != nil {
		return c.writer.RearHeadroom()
	}
	if c.service.mode == ModeUnsafeRaw {
		return 0
	}
	return snell.AEADTagLen
}

func (c *serverConn) WriterMTU() int {
	if c.writer != nil {
		return c.writer.WriterMTU()
	}
	if c.service.mode == ModeDefault {
		return c.service.profile.chunkMax
	}
	return maxPayload
}

func (c *serverConn) Upstream() any {
	return c.Conn
}

var (
	_ N.ExtendedConn               = (*serverConn)(nil)
	_ N.ReadWaiter                 = (*serverConn)(nil)
	_ snell.VectorisedWriteCreator = (*serverConn)(nil)
	_ N.VectorisedWriter           = (*serverVectorisedWriter)(nil)
	_ N.WriteCloser                = (*serverConn)(nil)
)
