package tproxy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/pool"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type packet struct {
	pc        net.PacketConn
	lAddr     netip.AddrPort
	buf       []byte
	tunnel    C.Tunnel
	additions []inbound.Addition
	source    C.NatSource
}

func (c *packet) Data() []byte {
	return c.buf
}

// WriteBack opens a new socket binding `addr` to write UDP packet back
func (c *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil || udpAddr.Port < 0 || udpAddr.Port > 65535 {
		return 0, fmt.Errorf("invalid tproxy UDP source address: %v", addr)
	}
	rAddr := udpAddr.AddrPort()
	if !rAddr.IsValid() {
		return 0, fmt.Errorf("invalid tproxy UDP source address: %v", addr)
	}
	if c.source == nil {
		return 0, fmt.Errorf("tproxy UDP source group is not bound")
	}
	return c.source.WithLocalConn(rAddr.String(), func() (*net.UDPConn, error) {
		conn, err := listenLocalConn(rAddr, c.lAddr, c.tunnel, c.additions...)
		if err != nil {
			log.Errorln("listenLocalConn failed with error: %s, packet loss (rAddr[%T]=%s lAddr[%T]=%s)", err.Error(), rAddr, rAddr, c.lAddr, c.lAddr)
		}
		return conn, err
	}, func(conn *net.UDPConn) (int, error) {
		return conn.Write(b)
	})
}

func (c *packet) BindNATSource(source C.NatSource) {
	// Keep the selected instance: looking up only lAddr during WriteBack could
	// attach a delayed reply to a newer source group after the old one closes.
	c.source = source
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *packet) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(c.lAddr)
}

func (c *packet) Drop() {
	_ = pool.Put(c.buf)
	c.buf = nil
}

func (c *packet) InAddr() net.Addr {
	return c.pc.LocalAddr()
}

// this function listen at rAddr
// and send what received to program itself, then send to real remote
func listenLocalConn(rAddr, lAddr netip.AddrPort, tunnel C.Tunnel, additions ...inbound.Addition) (*net.UDPConn, error) {
	lc, err := dialUDP("udp", rAddr, lAddr)
	if err != nil {
		return nil, err
	}
	go func() {
		log.Debugln("TProxy listenLocalConn rAddr=%s lAddr=%s", rAddr, lAddr)
		for {
			buf := pool.Get(pool.UDPBufferSize)
			br, err := lc.Read(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					log.Debugln("TProxy local conn listener exit.. rAddr=%s lAddr=%s", rAddr, lAddr)
					pool.Put(buf)
					return
				}
			}
			// since following localPackets are pass through this socket which listen rAddr
			// I choose current listener as packet's packet conn
			handlePacketConn(lc, tunnel, buf[:br], lAddr, rAddr, additions...)
		}
	}()
	return lc, nil
}
