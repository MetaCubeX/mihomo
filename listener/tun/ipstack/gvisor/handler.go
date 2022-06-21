//go:build !no_gvisor

package gvisor

import (
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/nnip"
	"github.com/Dreamacro/clash/common/pool"
	C "github.com/Dreamacro/clash/constant"
	D "github.com/Dreamacro/clash/listener/tun/ipstack/commons"
	"github.com/Dreamacro/clash/listener/tun/ipstack/gvisor/adapter"
	"github.com/Dreamacro/clash/transport/socks5"
)

var _ adapter.Handler = (*gvHandler)(nil)

type gvHandler struct {
	gateway   netip.Addr
	dnsHijack []netip.AddrPort

	tcpIn chan<- C.ConnContext
	udpIn chan<- *inbound.PacketAdapter
}

func (gh *gvHandler) HandleTCP(tunConn adapter.TCPConn) {
	id := tunConn.ID()

	rAddr := &net.TCPAddr{
		IP:   net.IP(id.LocalAddress),
		Port: int(id.LocalPort),
		Zone: "",
	}

	rAddrPort := netip.AddrPortFrom(nnip.IpToAddr(rAddr.IP), id.LocalPort)

	if D.ShouldHijackDns(gh.dnsHijack, rAddrPort) {
		go func() {
			buf := pool.Get(pool.UDPBufferSize)
			defer func() {
				_ = pool.Put(buf)
				_ = tunConn.Close()
			}()

			for {
				if tunConn.SetReadDeadline(time.Now().Add(D.DefaultDnsReadTimeout)) != nil {
					break
				}

				length := uint16(0)
				if err := binary.Read(tunConn, binary.BigEndian, &length); err != nil {
					break
				}

				if int(length) > len(buf) {
					break
				}

				n, err := tunConn.Read(buf[:length])
				if err != nil {
					break
				}

				msg, err := D.RelayDnsPacket(buf[:n])
				if err != nil {
					break
				}

				_, _ = tunConn.Write(msg)
			}
		}()

		return
	}

	gh.tcpIn <- inbound.NewSocket(socks5.ParseAddrToSocksAddr(rAddr), tunConn, C.TUN)
}

func (gh *gvHandler) HandleUDP(tunConn adapter.UDPConn) {
	id := tunConn.ID()

	rAddr := &net.UDPAddr{
		IP:   net.IP(id.LocalAddress),
		Port: int(id.LocalPort),
		Zone: "",
	}

	rAddrPort := netip.AddrPortFrom(nnip.IpToAddr(rAddr.IP), id.LocalPort)

	if rAddrPort.Addr() == gh.gateway {
		_ = tunConn.Close()
		return
	}

	target := socks5.ParseAddrToSocksAddr(rAddr)

	go func() {
		for {
			buf := pool.Get(pool.UDPBufferSize)

			n, addr, err := tunConn.ReadFrom(buf)
			if err != nil {
				_ = pool.Put(buf)
				break
			}

			payload := buf[:n]

			if D.ShouldHijackDns(gh.dnsHijack, rAddrPort) {
				go func() {
					defer func() {
						_ = pool.Put(buf)
					}()

					msg, err1 := D.RelayDnsPacket(payload)
					if err1 != nil {
						return
					}

					_, _ = tunConn.WriteTo(msg, addr)
				}()

				continue
			}

			gvPacket := &packet{
				pc:      tunConn,
				rAddr:   addr,
				payload: payload,
			}

			select {
			case gh.udpIn <- inbound.NewPacket(target, gvPacket, C.TUN):
			default:
			}
		}
	}()
}
