package tproxy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

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
}

func (c *packet) Data() []byte {
	return c.buf
}

// WriteBack opens a new socket binding `addr` to write UDP packet back
func (c *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	rAddr := addr.(*net.UDPAddr).AddrPort() // tunnel's handleUDPToLocal will ensure addr is *net.UDPAddr
	tc, err := createOrGetLocalConn(rAddr, c.lAddr, c.tunnel, c.additions...)
	if err != nil {
		return
	}
	n, err = tc.Write(b)
	if errors.Is(err, net.ErrClosed) {
		// the reader released tc (idle timeout) between our lookup and the write;
		// failing here would make the tunnel tear down the whole flow, so use a fresh conn
		tc, err = createOrGetLocalConn(rAddr, c.lAddr, c.tunnel, c.additions...)
		if err != nil {
			return
		}
		n, err = tc.Write(b)
	}
	if err == nil {
		// the flow is still alive, keep the reader from timing out
		_ = tc.SetReadDeadline(time.Now().Add(localConnIdleTimeout))
	}
	return
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

// this function listen at rAddr and write to lAddr
// for here, rAddr is the ip/port client want to access
// lAddr is the ip/port client opened
func createOrGetLocalConn(rAddr, lAddr netip.AddrPort, tunnel C.Tunnel, additions ...inbound.Addition) (*net.UDPConn, error) {
	remote := rAddr.String()
	local := lAddr.String()
	natTable := tunnel.NatTable()
	localConn := natTable.GetForLocalConn(local, remote)
	// localConn not exist
	if localConn == nil {
		cond, loaded := natTable.GetOrCreateLockForLocalConn(local, remote)
		if loaded {
			cond.L.Lock()
			cond.Wait()
			// we should get localConn here
			localConn = natTable.GetForLocalConn(local, remote)
			if localConn == nil {
				return nil, fmt.Errorf("localConn is nil, nat entry not exist")
			}
			cond.L.Unlock()
		} else {
			if cond == nil {
				return nil, fmt.Errorf("cond is nil, nat entry not exist")
			}
			defer func() {
				natTable.DeleteLockForLocalConn(local, remote)
				cond.Broadcast()
			}()
			conn, err := listenLocalConn(rAddr, lAddr, tunnel, additions...)
			if err != nil {
				log.Errorln("listenLocalConn failed with error: %s, packet loss (rAddr[%T]=%s lAddr[%T]=%s)", err.Error(), rAddr, remote, lAddr, local)
				return nil, err
			}
			natTable.AddForLocalConn(local, remote, conn)
			localConn = conn
		}
	}
	return localConn, nil
}

// this function listen at rAddr
// and send what received to program itself, then send to real remote
func listenLocalConn(rAddr, lAddr netip.AddrPort, tunnel C.Tunnel, additions ...inbound.Addition) (*net.UDPConn, error) {
	lc, err := dialUDP("udp", rAddr, lAddr)
	if err != nil {
		return nil, err
	}
	go serveLocalConn(lc, rAddr, lAddr, tunnel, localConnIdleTimeout, additions...)
	return lc, nil
}

// localConnIdleTimeout is how long a local conn may stay silent before it is released.
// It matches the tunnel's UDP NAT idle timeout (tunnel.udpTimeout).
var localConnIdleTimeout = 60 * time.Second

// serveLocalConn reads from lc and hands each packet to the tunnel.
// It returns once lc fails to read; unless lc was already closed, that means it
// stayed idle for `idle`, so lc and its nat entry are released too.
func serveLocalConn(lc *net.UDPConn, rAddr, lAddr netip.AddrPort, tunnel C.Tunnel, idle time.Duration, additions ...inbound.Addition) {
	log.Debugln("TProxy listenLocalConn rAddr=%s lAddr=%s", rAddr, lAddr)
	for {
		_ = lc.SetReadDeadline(time.Now().Add(idle))
		buf := pool.Get(pool.UDPBufferSize)
		br, err := lc.Read(buf)
		if err != nil {
			pool.Put(buf)
			if !errors.Is(err, net.ErrClosed) {
				// idle timeout or a socket error (e.g. ICMP refused); the next reply recreates the conn.
				// Only remove the nat entry if it still holds lc, a newer conn must stay.
				natTable := tunnel.NatTable()
				if natTable.GetForLocalConn(lAddr.String(), rAddr.String()) == lc {
					natTable.DeleteForLocalConn(lAddr.String(), rAddr.String())
				}
				_ = lc.Close()
			}
			log.Debugln("TProxy local conn listener exit.. rAddr=%s lAddr=%s err=%v", rAddr, lAddr, err)
			return
		}
		// since following localPackets are pass through this socket which listen rAddr
		// I choose current listener as packet's packet conn
		handlePacketConn(lc, tunnel, buf[:br], lAddr, rAddr, additions...)
	}
}
