package sing

import (
	"context"
	"errors"
	"golang.org/x/exp/slices"
	"net"
	"sync"
	"time"

	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/transport/socks5"

	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

const UDPTimeout = 5 * time.Minute

type ListenerHandler struct {
	TcpIn     chan<- C.ConnContext
	UdpIn     chan<- C.PacketAdapter
	Type      C.Type
	Additions []inbound.Addition
}

type waitCloseConn struct {
	net.Conn
	wg    *sync.WaitGroup
	close sync.Once
	rAddr net.Addr
}

func (c *waitCloseConn) Close() error { // call from handleTCPConn(connCtx C.ConnContext)
	c.close.Do(func() {
		c.wg.Done()
	})
	return c.Conn.Close()
}

func (c *waitCloseConn) RemoteAddr() net.Addr {
	return c.rAddr
}

func (c *waitCloseConn) Upstream() any {
	return c.Conn
}

func (h *ListenerHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	additions := h.Additions
	if ctxAdditions := getAdditions(ctx); len(ctxAdditions) > 0 {
		additions = slices.Clone(additions)
		additions = append(additions, ctxAdditions...)
	}
	switch metadata.Destination.Fqdn {
	case vmess.MuxDestination.Fqdn:
		return vmess.HandleMuxConnection(ctx, conn, h)
	case uot.UOTMagicAddress:
		metadata.Destination = M.Socksaddr{}
		return h.NewPacketConnection(ctx, uot.NewClientConn(conn), metadata)
	}
	target := socks5.ParseAddr(metadata.Destination.String())
	wg := &sync.WaitGroup{}
	defer wg.Wait() // this goroutine must exit after conn.Close()
	wg.Add(1)

	h.TcpIn <- inbound.NewSocket(target, &waitCloseConn{Conn: conn, wg: wg, rAddr: metadata.Source.TCPAddr()}, h.Type, additions...)
	return nil
}

func (h *ListenerHandler) NewPacketConnection(ctx context.Context, conn network.PacketConn, metadata M.Metadata) error {
	additions := h.Additions
	if ctxAdditions := getAdditions(ctx); len(ctxAdditions) > 0 {
		additions = slices.Clone(additions)
		additions = append(additions, ctxAdditions...)
	}
	defer func() { _ = conn.Close() }()
	mutex := sync.Mutex{}
	conn2 := conn // a new interface to set nil in defer
	defer func() {
		mutex.Lock() // this goroutine must exit after all conn.WritePacket() is not running
		defer mutex.Unlock()
		conn2 = nil
	}()
	for {
		buff := buf.NewPacket() // do not use stack buffer
		dest, err := conn.ReadPacket(buff)
		if err != nil {
			buff.Release()
			if E.IsClosed(err) {
				break
			}
			return err
		}
		target := socks5.ParseAddr(dest.String())
		packet := &packet{
			conn:  &conn2,
			mutex: &mutex,
			rAddr: metadata.Source.UDPAddr(),
			lAddr: conn.LocalAddr(),
			buff:  buff,
		}
		select {
		case h.UdpIn <- inbound.NewPacket(target, packet, h.Type, additions...):
		default:
		}
	}
	return nil
}

func (h *ListenerHandler) NewError(ctx context.Context, err error) {
	log.Warnln("%s listener get error: %+v", h.Type.String(), err)
}

type packet struct {
	conn  *network.PacketConn
	mutex *sync.Mutex
	rAddr net.Addr
	lAddr net.Addr
	buff  *buf.Buffer
}

func (c *packet) Data() []byte {
	return c.buff.Bytes()
}

// WriteBack wirtes UDP packet with source(ip, port) = `addr`
func (c *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	if addr == nil {
		err = errors.New("address is invalid")
		return
	}
	buff := buf.NewPacket()
	defer buff.Release()
	n, err = buff.Write(b)
	if err != nil {
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()
	conn := *c.conn
	if conn == nil {
		err = errors.New("writeBack to closed connection")
		return
	}
	err = conn.WritePacket(buff, M.SocksaddrFromNet(addr))
	return
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *packet) LocalAddr() net.Addr {
	return c.rAddr
}

func (c *packet) Drop() {
	c.buff.Release()
}

func (c *packet) InAddr() net.Addr {
	return c.lAddr
}
