package udphop

import (
	"errors"
	"math/rand"
	"net"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/log"
)

const defaultHopInterval = 30 * time.Second

type udpHopPacketConn struct {
	Addrs       []net.Addr
	HopInterval time.Duration

	conn      net.PacketConn
	addrIndex int

	closeChan chan struct{}
	closed    bool
}

type udpPacket struct {
	Buf  []byte
	N    int
	Addr net.Addr
	Err  error
}

func NewUDPHopPacketConn(addr *UDPHopAddr, hopInterval time.Duration) (net.PacketConn, error) {
	if hopInterval == 0 {
		hopInterval = defaultHopInterval
	} else if hopInterval < 5*time.Second {
		return nil, errors.New("hop interval must be at least 5 seconds")
	}
	addrs, err := addr.addrs()
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	index := rand.Intn(len(addrs))
	hConn := &udpHopPacketConn{
		Addrs:       addrs,
		HopInterval: hopInterval,
		conn:        conn,
		addrIndex:   index,
	}
	go hConn.hopLoop()
	return hConn, nil
}

func (u *udpHopPacketConn) hopLoop() {
	ticker := time.NewTicker(u.HopInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			u.hop()
		case <-u.closeChan:
			return
		}
	}
}

func (u *udpHopPacketConn) hop() {
	if u.closed {
		return
	}
	u.addrIndex = rand.Intn(len(u.Addrs))
	log.Infoln("hopped to %s", u.Addrs[u.addrIndex])
}

func (u *udpHopPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	return u.conn.ReadFrom(b)
}

func (u *udpHopPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if u.closed {
		return 0, net.ErrClosed
	}
	return u.conn.WriteTo(b, u.Addrs[u.addrIndex])
}

func (u *udpHopPacketConn) Close() error {
	if u.closed {
		return nil
	}
	err := u.conn.Close()
	close(u.closeChan)
	u.closed = true
	u.Addrs = nil // For GC
	return err
}

func (u *udpHopPacketConn) LocalAddr() net.Addr {
	return u.conn.LocalAddr()
}

func (u *udpHopPacketConn) SetDeadline(t time.Time) error {
	return u.conn.SetDeadline(t)
}

func (u *udpHopPacketConn) SetReadDeadline(t time.Time) error {
	return u.conn.SetReadDeadline(t)
}

func (u *udpHopPacketConn) SetWriteDeadline(t time.Time) error {
	return u.conn.SetWriteDeadline(t)
}

// UDP-specific methods below

func (u *udpHopPacketConn) SetReadBuffer(bytes int) error {
	return trySetReadBuffer(u.conn, bytes)
}

func (u *udpHopPacketConn) SetWriteBuffer(bytes int) error {
	return trySetWriteBuffer(u.conn, bytes)
}

func (u *udpHopPacketConn) SyscallConn() (syscall.RawConn, error) {
	sc, ok := u.conn.(syscall.Conn)
	if !ok {
		return nil, errors.New("not supported")
	}
	return sc.SyscallConn()
}

func trySetReadBuffer(pc net.PacketConn, bytes int) error {
	sc, ok := pc.(interface {
		SetReadBuffer(bytes int) error
	})
	if ok {
		return sc.SetReadBuffer(bytes)
	}
	return nil
}

func trySetWriteBuffer(pc net.PacketConn, bytes int) error {
	sc, ok := pc.(interface {
		SetWriteBuffer(bytes int) error
	})
	if ok {
		return sc.SetWriteBuffer(bytes)
	}
	return nil
}
