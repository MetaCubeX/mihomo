package mkcp

import (
	"io"
	"net"
	"sync/atomic"

	"github.com/metacubex/randv2"
)

var globalConv = randv2.Uint32()

// packetConnWrapper turns an unconnected net.PacketConn into a stream-like
// io.ReadWriteCloser bound to a single remote address, which is what the mKCP
// Connection expects as its underlying transport.
type packetConnWrapper struct {
	net.PacketConn
	remote net.Addr
}

func (c *packetConnWrapper) Read(b []byte) (int, error) {
	n, _, err := c.PacketConn.ReadFrom(b)
	return n, err
}

func (c *packetConnWrapper) Write(b []byte) (int, error) {
	return c.PacketConn.WriteTo(b, c.remote)
}

func (c *packetConnWrapper) RemoteAddr() net.Addr {
	return c.remote
}

func fetchInput(input io.Reader, reader PacketReader, conn *Connection) {
	cache := make(chan *Buffer, 1024)
	go func() {
		for {
			payload := New()
			if _, err := payload.ReadFrom(input); err != nil {
				payload.Release()
				close(cache)
				return
			}
			select {
			case cache <- payload:
			default:
				payload.Release()
			}
		}
	}()

	for payload := range cache {
		segments := reader.Read(payload.Bytes())
		payload.Release()
		if len(segments) > 0 {
			conn.Input(segments)
		}
	}
}

// Dial wraps an established UDP net.PacketConn into an mKCP *Connection talking
// to remote. The returned Connection implements net.Conn. It takes ownership of
// pc and closes it when the connection terminates.
func Dial(pc net.PacketConn, remote net.Addr, config *Config) (*Connection, error) {
	conv := uint16(atomic.AddUint32(&globalConv, 1))
	return dialConv(pc, remote, config, conv)
}

// dialConv is Dial with an explicit conversation id, used by Dial and tests.
func dialConv(pc net.PacketConn, remote net.Addr, config *Config, conv uint16) (*Connection, error) {
	if config == nil {
		config = &Config{}
	}

	header, err := config.GetPackerHeader()
	if err != nil {
		return nil, err
	}
	security, err := config.GetSecurity()
	if err != nil {
		return nil, err
	}

	rawConn := &packetConnWrapper{PacketConn: pc, remote: remote}
	reader := &KCPPacketReader{
		Header:   header,
		Security: security,
	}
	writer := &KCPPacketWriter{
		Header:   header,
		Security: security,
		Writer:   rawConn,
	}

	session := NewConnection(ConnMetadata{
		LocalAddr:    pc.LocalAddr(),
		RemoteAddr:   remote,
		Conversation: conv,
	}, writer, rawConn, config)

	go fetchInput(rawConn, reader, session)

	return session, nil
}
