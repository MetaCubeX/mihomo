package system

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/pool"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/listener/tun/device"
	"github.com/Dreamacro/clash/listener/tun/ipstack"
	D "github.com/Dreamacro/clash/listener/tun/ipstack/commons"
	"github.com/Dreamacro/clash/listener/tun/ipstack/system/mars"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/transport/socks5"
)

type sysStack struct {
	stack  io.Closer
	device device.Device
}

func (s sysStack) Close() error {
	if s.stack != nil {
		_ = s.stack.Close()
	}
	if s.device != nil {
		_ = s.device.Close()
	}
	return nil
}

var ipv4LoopBack = netip.MustParsePrefix("127.0.0.0/8")

func New(device device.Device, dnsHijack []netip.AddrPort, tunAddress netip.Prefix, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (ipstack.Stack, error) {
	portal := tunAddress.Addr()
	gateway := portal

	stack, err := mars.StartListener(device, gateway, portal)
	if err != nil {
		_ = device.Close()

		return nil, err
	}

	dnsAddr := dnsHijack

	tcp := func() {
		defer stack.TCP().Close()
		defer log.Debugln("TCP: closed")

		for stack.TCP().SetDeadline(time.Time{}) == nil {
			conn, err := stack.TCP().Accept()
			if err != nil {
				log.Debugln("Accept connection: %v", err)

				continue
			}

			lAddr := conn.LocalAddr().(*net.TCPAddr)
			rAddr := conn.RemoteAddr().(*net.TCPAddr)

			rAddrIp, _ := netip.AddrFromSlice(rAddr.IP)
			rAddrPort := netip.AddrPortFrom(rAddrIp, uint16(rAddr.Port))

			if ipv4LoopBack.Contains(rAddrIp) {
				conn.Close()

				continue
			}

			if D.ShouldHijackDns(dnsAddr, rAddrPort) {
				go func() {
					log.Debugln("[TUN] hijack dns tcp: %s", rAddrPort.String())

					defer conn.Close()

					buf := pool.Get(pool.UDPBufferSize)
					defer pool.Put(buf)

					for {
						conn.SetReadDeadline(time.Now().Add(C.DefaultTCPTimeout))

						length := uint16(0)
						if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
							break
						}

						if int(length) > len(buf) {
							break
						}

						n, err := conn.Read(buf[:length])
						if err != nil {
							break
						}

						msg, err := D.RelayDnsPacket(buf[:n])
						if err != nil {
							break
						}

						_, _ = conn.Write(msg)
					}
				}()

				continue
			}

			metadata := &C.Metadata{
				NetWork:  C.TCP,
				Type:     C.TUN,
				SrcIP:    lAddr.IP,
				DstIP:    rAddr.IP,
				SrcPort:  strconv.Itoa(lAddr.Port),
				DstPort:  strconv.Itoa(rAddr.Port),
				AddrType: C.AtypIPv4,
				Host:     "",
			}

			tcpIn <- context.NewConnContext(conn, metadata)
		}
	}

	udp := func() {
		defer stack.UDP().Close()
		defer log.Debugln("UDP: closed")

		for {
			buf := pool.Get(pool.UDPBufferSize)

			n, lRAddr, rRAddr, err := stack.UDP().ReadFrom(buf)
			if err != nil {
				return
			}

			raw := buf[:n]
			lAddr := lRAddr.(*net.UDPAddr)
			rAddr := rRAddr.(*net.UDPAddr)

			rAddrIp, _ := netip.AddrFromSlice(rAddr.IP)
			rAddrPort := netip.AddrPortFrom(rAddrIp, uint16(rAddr.Port))

			if ipv4LoopBack.Contains(rAddrIp) {
				pool.Put(buf)

				continue
			}

			if D.ShouldHijackDns(dnsAddr, rAddrPort) {
				go func() {
					defer pool.Put(buf)

					msg, err := D.RelayDnsPacket(raw)
					if err != nil {
						return
					}

					_, _ = stack.UDP().WriteTo(msg, rAddr, lAddr)

					log.Debugln("[TUN] hijack dns udp: %s", rAddrPort.String())
				}()

				continue
			}

			pkt := &packet{
				local: lAddr,
				data:  raw,
				writeBack: func(b []byte, addr net.Addr) (int, error) {
					return stack.UDP().WriteTo(b, addr, lAddr)
				},
				drop: func() {
					pool.Put(buf)
				},
			}

			udpIn <- inbound.NewPacket(socks5.ParseAddrToSocksAddr(rAddr), pkt, C.TUN)
		}
	}

	go tcp()
	go udp()
	go udp()

	return &sysStack{stack: stack, device: device}, nil
}
