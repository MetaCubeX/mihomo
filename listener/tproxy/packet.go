package tproxy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/pool"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

type packet struct {
	pc       net.PacketConn
	lAddr    netip.AddrPort
	buf      []byte
	in       chan<- C.PacketAdapter
	natTable C.NatTable
}

func (c *packet) Data() []byte {
	return c.buf
}

// WriteBack opens a new socket binding `addr` to write UDP packet back
func (c *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	tc, err := createOrGetLocalConn(addr, c.LocalAddr(), c.in, c.natTable)
	if err != nil {
		n = 0
		return
	}
	n, err = tc.Write(b)
	return
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *packet) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: c.lAddr.Addr().AsSlice(), Port: int(c.lAddr.Port()), Zone: c.lAddr.Addr().Zone()}
}

func (c *packet) Drop() {
	pool.Put(c.buf)
}

func (c *packet) InAddr() net.Addr {
	return c.pc.LocalAddr()
}

// this function listen at rAddr and write to lAddr
// for here, rAddr is the ip/port client want to access
// lAddr is the ip/port client opened
func createOrGetLocalConn(rAddr, lAddr net.Addr, in chan<- C.PacketAdapter, natTable C.NatTable) (*net.UDPConn, error) {
	remote := rAddr.String()
	local := lAddr.String()
	localConn := natTable.GetLocalConn(local, remote)
	// localConn not exist
	if localConn == nil {
		lockKey := remote + "-lock"
		cond, loaded := natTable.GetOrCreateLockForLocalConn(local, lockKey)
		if loaded {
			cond.L.Lock()
			cond.Wait()
			// we should get localConn here
			localConn = natTable.GetLocalConn(local, remote)
			if localConn == nil {
				return nil, fmt.Errorf("localConn is nil, nat entry not exist")
			}
			cond.L.Unlock()
		} else {
			if cond == nil {
				return nil, fmt.Errorf("cond is nil, nat entry not exist")
			}
			defer func() {
				natTable.DeleteLocalConnMap(local, lockKey)
				cond.Broadcast()
			}()
			conn, err := listenLocalConn(rAddr, lAddr, in, natTable)
			if err != nil {
				log.Errorln("listenLocalConn failed with error: %s, packet loss", err.Error())
				return nil, err
			}
			natTable.AddLocalConn(local, remote, conn)
			localConn = conn
		}
	}
	return localConn, nil
}

// this function listen at rAddr
// and send what received to program itself, then send to real remote
func listenLocalConn(rAddr, lAddr net.Addr, in chan<- C.PacketAdapter, natTable C.NatTable) (*net.UDPConn, error) {
	additions := []inbound.Addition{
		inbound.WithInName("DEFAULT-TPROXY"),
		inbound.WithSpecialRules(""),
	}
	lc, err := dialUDP("udp", rAddr.(*net.UDPAddr).AddrPort(), lAddr.(*net.UDPAddr).AddrPort())
	if err != nil {
		return nil, err
	}
	go func() {
		log.Debugln("TProxy listenLocalConn rAddr=%s lAddr=%s", rAddr.String(), lAddr.String())
		for {
			buf := pool.Get(pool.UDPBufferSize)
			br, err := lc.Read(buf)
			if err != nil {
				pool.Put(buf)
				if errors.Is(err, net.ErrClosed) {
					log.Debugln("TProxy local conn listener exit.. rAddr=%s lAddr=%s", rAddr.String(), lAddr.String())
					return
				}
			}
			// since following localPackets are pass through this socket which listen rAddr
			// I choose current listener as packet's packet conn
			handlePacketConn(lc, in, natTable, buf[:br], lAddr.(*net.UDPAddr).AddrPort(), rAddr.(*net.UDPAddr).AddrPort(), additions...)
		}
	}()
	return lc, nil
}
