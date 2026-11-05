package snellv6

import (
	"io"
	"net"
	"os"
	"sync"

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
	maxUDPRequestHeaderLen  = 1 + 1 + 255 + 2
	maxUDPResponseHeaderLen = 1 + 16 + 2
)

func (c *clientPacketConn) udpRequestAddrLen(destination M.Socksaddr) int {
	if destination.IsIP() {
		if destination.Unwrap().Addr.Is4() {
			return 1 + 1 + 4 + 2
		}
		return 1 + 1 + 16 + 2
	}
	return 1 + len(destination.Fqdn) + 2
}

type clientPacketConn struct {
	net.Conn
	client *Client

	writeAccess sync.Mutex
	writer      reuse.RecordWriter

	readAccess sync.Mutex
	reader     reuse.RecordReader

	readWaitOptions N.ReadWaitOptions
}

func (c *clientPacketConn) writeRequest() error {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if c.writer != nil {
		return nil
	}
	requestPayload := snell.Request{Command: snell.CommandUDP, ClientID: c.client.userKey}
	request := buf.NewSize(requestPayload.Len())
	err := requestPayload.Write(request)
	if err != nil {
		request.Release()
		return err
	}
	writer, err := writeFirstRecord(c.Conn, c.client.mode, c.client.psk, c.client.profile, request.Bytes())
	request.Release()
	if err != nil {
		return E.Cause(err, "write udp request")
	}
	c.writer = writer
	return nil
}

func (c *clientPacketConn) readReply() (reuse.RecordReader, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	if c.reader != nil {
		return c.reader, nil
	}
	reader, record, err := readFirstRecord(c.Conn, c.client.mode, c.client.psk, c.client.profile, c.readWaitOptions)
	if err != nil {
		return nil, E.Cause(err, "read udp reply")
	}
	cached, err := reuse.ParseReply(record)
	if err != nil {
		return nil, err
	}
	reader.SetCache(cached)
	c.reader = reader
	return reader, nil
}

func (c *clientPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	err := c.writeRequest()
	if err != nil {
		buffer.Release()
		return err
	}
	_, err = c.readReply()
	if err != nil {
		buffer.Release()
		return err
	}
	header := buf.With(buffer.ExtendHeader(1 + c.udpRequestAddrLen(destination)))
	common.Must(header.WriteByte(snell.UDPCommandForward))
	err = snell.WriteUDPRequestAddress(header, destination)
	if err != nil {
		buffer.Release()
		return err
	}
	if buffer.Len() > maxPayload {
		buffer.Release()
		return snell.ErrPayloadTooLarge
	}
	return c.writer.WritePacketBuffer(buffer)
}

func (c *clientPacketConn) CreatePacketBatchWriter() (snell.PacketBatchWriter, bool) {
	upstreamWriter, created := bufio.CreateVectorisedWriter(c.Conn)
	if !created {
		return nil, false
	}
	return &clientPacketBatchWriter{conn: c, upstream: upstreamWriter}, true
}

type clientPacketBatchWriter struct {
	conn     *clientPacketConn
	upstream N.VectorisedWriter

	access sync.Mutex
	writer N.VectorisedWriter
}

func (w *clientPacketBatchWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	if len(buffers) == 0 || len(buffers) != len(destinations) {
		buf.ReleaseMulti(buffers)
		return os.ErrInvalid
	}
	w.access.Lock()
	if w.writer == nil {
		err := w.conn.writeRequest()
		if err != nil {
			w.access.Unlock()
			buf.ReleaseMulti(buffers)
			return err
		}
		_, err = w.conn.readReply()
		if err != nil {
			w.access.Unlock()
			buf.ReleaseMulti(buffers)
			return err
		}
		w.writer = w.conn.writer.CreatePacketVectorisedWriterFor(w.upstream)
	}
	recordWriter := w.writer
	w.access.Unlock()
	for index, buffer := range buffers {
		header := buf.With(buffer.ExtendHeader(1 + w.conn.udpRequestAddrLen(destinations[index])))
		common.Must(header.WriteByte(snell.UDPCommandForward))
		err := snell.WriteUDPRequestAddress(header, destinations[index])
		if err != nil {
			buf.ReleaseMulti(buffers)
			return err
		}
	}
	return recordWriter.WriteVectorised(buffers)
}

func (c *clientPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	reader, err := c.readReply()
	if err != nil {
		return M.Socksaddr{}, err
	}
	record, err := reader.NextRecord()
	if err != nil {
		return M.Socksaddr{}, err
	}
	destination, err := snell.ReadUDPResponseAddress(record)
	if err != nil {
		record.Release()
		return M.Socksaddr{}, err
	}
	if record.Len() > buffer.FreeLen() {
		record.Release()
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	_, err = buffer.Write(record.Bytes())
	record.Release()
	if err != nil {
		return M.Socksaddr{}, err
	}
	return destination, nil
}

func (c *clientPacketConn) FrontHeadroom() int {
	switch c.client.mode {
	case ModeUnsafeRaw:
		return snell.HeaderPlainLen + maxUDPRequestHeaderLen
	case ModeUnshaped:
		return snell.HeaderCipherLen + maxUDPRequestHeaderLen
	default:
		return c.client.profile.recordPrefixMax + snell.HeaderCipherLen + c.client.profile.padMaxHeadroom + maxUDPRequestHeaderLen
	}
}

func (c *clientPacketConn) RearHeadroom() int {
	if c.client.mode == ModeUnsafeRaw {
		return 0
	}
	return snell.AEADTagLen
}

func (c *clientPacketConn) WriterMTU() int {
	return maxPayload - maxUDPRequestHeaderLen
}

func (c *clientPacketConn) Upstream() any {
	return c.Conn
}

func (c *clientPacketConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	c.readWaitOptions = options
	if c.reader != nil {
		c.reader.InitializeReadWaiter(options)
	}
	return false
}

func (c *clientPacketConn) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	reader, err := c.readReply()
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	record, err := reader.WaitReadBuffer()
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	destination, err := snell.ReadUDPResponseAddress(record)
	if err != nil {
		record.Release()
		return nil, M.Socksaddr{}, err
	}
	return record, destination, nil
}

type serverPacketConn struct {
	net.Conn
	service         *Service
	reader          reuse.RecordReader
	readWaitOptions N.ReadWaitOptions

	writeAccess sync.Mutex
	writer      reuse.RecordWriter
}

func (c *serverPacketConn) responseAddrLen(source M.Socksaddr) int {
	if source.Unwrap().Addr.Is4() {
		return 1 + 4 + 2
	}
	return 1 + 16 + 2
}

func (c *serverPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	record, err := c.reader.NextRecord()
	if err != nil {
		return M.Socksaddr{}, err
	}
	command, err := record.ReadByte()
	if err != nil {
		record.Release()
		return M.Socksaddr{}, err
	}
	if command != snell.UDPCommandForward {
		record.Release()
		return M.Socksaddr{}, E.Extend(snell.ErrUnsupportedCommand, "udp ", command)
	}
	destination, err := snell.ReadUDPRequestAddress(record)
	if err != nil {
		record.Release()
		return M.Socksaddr{}, err
	}
	if record.Len() > buffer.FreeLen() {
		record.Release()
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	_, err = buffer.Write(record.Bytes())
	record.Release()
	if err != nil {
		return M.Socksaddr{}, err
	}
	return destination, nil
}

func (c *serverPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.writeAccess.Lock()
	if c.writer == nil {
		err := c.writeTunnelReply()
		if err != nil {
			c.writeAccess.Unlock()
			buffer.Release()
			return err
		}
	}
	writer := c.writer
	c.writeAccess.Unlock()
	header := buf.With(buffer.ExtendHeader(c.responseAddrLen(destination)))
	err := snell.WriteUDPResponseAddress(header, destination)
	if err != nil {
		buffer.Release()
		return err
	}
	if buffer.Len() > maxPayload {
		buffer.Release()
		return snell.ErrPayloadTooLarge
	}
	return writer.WritePacketBuffer(buffer)
}

func (c *serverPacketConn) CreatePacketBatchWriter() (snell.PacketBatchWriter, bool) {
	upstreamWriter, created := bufio.CreateVectorisedWriter(c.Conn)
	if !created {
		return nil, false
	}
	return &serverPacketBatchWriter{conn: c, upstream: upstreamWriter}, true
}

type serverPacketBatchWriter struct {
	conn     *serverPacketConn
	upstream N.VectorisedWriter

	access sync.Mutex
	writer N.VectorisedWriter
}

func (w *serverPacketBatchWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	if len(buffers) == 0 || len(buffers) != len(destinations) {
		buf.ReleaseMulti(buffers)
		return os.ErrInvalid
	}
	w.access.Lock()
	if w.writer == nil {
		w.conn.writeAccess.Lock()
		if w.conn.writer == nil {
			err := w.conn.writeTunnelReply()
			if err != nil {
				w.conn.writeAccess.Unlock()
				w.access.Unlock()
				buf.ReleaseMulti(buffers)
				return err
			}
		}
		w.writer = w.conn.writer.CreatePacketVectorisedWriterFor(w.upstream)
		w.conn.writeAccess.Unlock()
	}
	recordWriter := w.writer
	w.access.Unlock()
	for index, buffer := range buffers {
		header := buf.With(buffer.ExtendHeader(w.conn.responseAddrLen(destinations[index])))
		err := snell.WriteUDPResponseAddress(header, destinations[index])
		if err != nil {
			buf.ReleaseMulti(buffers)
			return err
		}
	}
	return recordWriter.WriteVectorised(buffers)
}

func (c *serverPacketConn) writeTunnelReply() error {
	reply := [1]byte{snell.ReplyTunnel}
	if c.writer != nil {
		_, err := c.writer.Write(reply[:])
		if err != nil {
			return E.Cause(err, "write udp reply")
		}
		return nil
	}
	writer, err := writeFirstRecord(c.Conn, c.service.mode, c.service.psk, c.service.profile, reply[:])
	if err != nil {
		return E.Cause(err, "write udp reply")
	}
	c.writer = writer
	return nil
}

func (c *serverPacketConn) FrontHeadroom() int {
	switch c.service.mode {
	case ModeUnsafeRaw:
		return snell.HeaderPlainLen + maxUDPResponseHeaderLen
	case ModeUnshaped:
		return snell.HeaderCipherLen + maxUDPResponseHeaderLen
	default:
		return c.service.profile.recordPrefixMax + snell.HeaderCipherLen + c.service.profile.padMaxHeadroom + maxUDPResponseHeaderLen
	}
}

func (c *serverPacketConn) RearHeadroom() int {
	if c.service.mode == ModeUnsafeRaw {
		return 0
	}
	return snell.AEADTagLen
}

func (c *serverPacketConn) WriterMTU() int {
	return maxPayload - maxUDPResponseHeaderLen
}

func (c *serverPacketConn) Upstream() any {
	return c.Conn
}

func (c *serverPacketConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readWaitOptions = options
	c.reader.InitializeReadWaiter(options)
	return false
}

func (c *serverPacketConn) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	record, err := c.reader.WaitReadBuffer()
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	command, err := record.ReadByte()
	if err != nil {
		record.Release()
		return nil, M.Socksaddr{}, err
	}
	if command != snell.UDPCommandForward {
		record.Release()
		return nil, M.Socksaddr{}, E.Extend(snell.ErrUnsupportedCommand, "udp ", command)
	}
	destination, err := snell.ReadUDPRequestAddress(record)
	if err != nil {
		record.Release()
		return nil, M.Socksaddr{}, err
	}
	return record, destination, nil
}

var (
	_ N.PacketConn                  = (*clientPacketConn)(nil)
	_ N.PacketReadWaiter            = (*clientPacketConn)(nil)
	_ snell.PacketBatchWriteCreator = (*clientPacketConn)(nil)
	_ N.WriterWithMTU               = (*clientPacketConn)(nil)
	_ snell.PacketBatchWriter       = (*clientPacketBatchWriter)(nil)
	_ N.PacketConn                  = (*serverPacketConn)(nil)
	_ N.PacketReadWaiter            = (*serverPacketConn)(nil)
	_ snell.PacketBatchWriteCreator = (*serverPacketConn)(nil)
	_ N.WriterWithMTU               = (*serverPacketConn)(nil)
	_ snell.PacketBatchWriter       = (*serverPacketBatchWriter)(nil)
)
