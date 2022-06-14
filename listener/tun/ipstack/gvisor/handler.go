package gvisor

import (
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/pool"
	C "github.com/Dreamacro/clash/constant"
	D "github.com/Dreamacro/clash/listener/tun/ipstack/commons"
	"github.com/Dreamacro/clash/listener/tun/ipstack/gvisor/adapter"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/transport/socks5"
)

var _ adapter.Handler = (*gvHandler)(nil)

type gvHandler struct {
	gateway   netip.Addr
	dnsHijack []C.DNSUrl

	tcpIn chan<- C.ConnContext
	udpIn chan<- *inbound.PacketAdapter
}

func (gh *gvHandler) HandleTCP(tunConn adapter.TCPConn) {
	rAddrPort := tunConn.LocalAddr().(*net.TCPAddr).AddrPort()

	if D.ShouldHijackDns(gh.dnsHijack, rAddrPort, "tcp") {
		go func() {
			log.Debugln("[TUN] hijack dns tcp: %s", rAddrPort.String())

			buf := pool.Get(pool.UDPBufferSize)
			defer func() {
				_ = tunConn.Close()
				_ = pool.Put(buf)
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

	gh.tcpIn <- inbound.NewSocket(socks5.AddrFromStdAddrPort(rAddrPort), tunConn, C.TUN)
}

func (gh *gvHandler) HandleUDP(tunConn adapter.UDPConn) {
	rAddrPort := tunConn.LocalAddr().(*net.UDPAddr).AddrPort()

	if rAddrPort.Addr() == gh.gateway {
		_ = tunConn.Close()
		return
	}

	target := socks5.AddrFromStdAddrPort(rAddrPort)

	go func() {
		for {
			buf := pool.Get(pool.UDPBufferSize)

			n, addr, err := tunConn.ReadFrom(buf)
			if err != nil {
				_ = pool.Put(buf)
				break
			}

			if D.ShouldHijackDns(gh.dnsHijack, rAddrPort, "udp") {
				go func() {
					defer func() {
						_ = pool.Put(buf)
					}()

					msg, err1 := D.RelayDnsPacket(buf[:n])
					if err1 != nil {
						return
					}

					_, _ = tunConn.WriteTo(msg, addr)

					log.Debugln("[TUN] hijack dns udp: %s", rAddrPort.String())
				}()

				continue
			}

			gvPacket := &packet{
				pc:      tunConn,
				rAddr:   addr,
				payload: buf,
				offset:  n,
			}

			select {
			case gh.udpIn <- inbound.NewPacket(target, gvPacket, C.TUN):
			default:
				gvPacket.Drop()
			}
		}
	}()
}
