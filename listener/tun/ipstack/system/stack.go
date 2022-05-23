package system

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/nnip"
	"github.com/Dreamacro/clash/common/pool"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/listener/tun/device"
	"github.com/Dreamacro/clash/listener/tun/ipstack"
	D "github.com/Dreamacro/clash/listener/tun/ipstack/commons"
	"github.com/Dreamacro/clash/listener/tun/ipstack/system/mars"
	"github.com/Dreamacro/clash/listener/tun/ipstack/system/mars/nat"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/transport/socks5"
)

type sysStack struct {
	stack  io.Closer
	device device.Device

	closed bool
	once   sync.Once
	wg     sync.WaitGroup
}

func (s *sysStack) Close() error {
	defer func() {
		if s.device != nil {
			_ = s.device.Close()
		}
	}()

	s.closed = true

	err := s.stack.Close()

	s.wg.Wait()

	return err
}

func New(device device.Device, dnsHijack []netip.AddrPort, tunAddress netip.Prefix, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (ipstack.Stack, error) {
	var (
		gateway   = tunAddress.Masked().Addr().Next()
		portal    = gateway.Next()
		broadcast = nnip.UnMasked(tunAddress)
	)

	stack, err := mars.StartListener(device, gateway, portal, broadcast)
	if err != nil {
		_ = device.Close()

		return nil, err
	}

	ipStack := &sysStack{stack: stack, device: device}

	dnsAddr := dnsHijack

	tcp := func() {
		defer func(tcp *nat.TCP) {
			_ = tcp.Close()
		}(stack.TCP())

		for !ipStack.closed {
			conn, err := stack.TCP().Accept()
			if err != nil {
				log.Debugln("[STACK] accept connection error: %v", err)
				continue
			}

			lAddr := conn.LocalAddr().(*net.TCPAddr)
			rAddr := conn.RemoteAddr().(*net.TCPAddr)

			lAddrPort := netip.AddrPortFrom(nnip.IpToAddr(lAddr.IP), uint16(lAddr.Port))
			rAddrPort := netip.AddrPortFrom(nnip.IpToAddr(rAddr.IP), uint16(rAddr.Port))

			if rAddrPort.Addr().IsLoopback() {
				_ = conn.Close()

				continue
			}

			if D.ShouldHijackDns(dnsAddr, rAddrPort) {
				go func() {
					buf := pool.Get(pool.UDPBufferSize)
					defer func() {
						_ = pool.Put(buf)
						_ = conn.Close()
					}()

					for {
						if conn.SetReadDeadline(time.Now().Add(C.DefaultTCPTimeout)) != nil {
							break
						}

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
				SrcIP:    lAddrPort.Addr(),
				DstIP:    rAddrPort.Addr(),
				SrcPort:  strconv.Itoa(lAddr.Port),
				DstPort:  strconv.Itoa(rAddr.Port),
				AddrType: C.AtypIPv4,
				Host:     "",
			}

			tcpIn <- context.NewConnContext(conn, metadata)
		}

		ipStack.wg.Done()
	}

	udp := func() {
		defer func(udp *nat.UDP) {
			_ = udp.Close()
		}(stack.UDP())

		for !ipStack.closed {
			buf := pool.Get(pool.UDPBufferSize)

			n, lRAddr, rRAddr, err := stack.UDP().ReadFrom(buf)
			if err != nil {
				_ = pool.Put(buf)
				break
			}

			raw := buf[:n]
			lAddr := lRAddr.(*net.UDPAddr)
			rAddr := rRAddr.(*net.UDPAddr)

			rAddrPort := netip.AddrPortFrom(nnip.IpToAddr(rAddr.IP), uint16(rAddr.Port))

			if rAddrPort.Addr().IsLoopback() || rAddrPort.Addr() == gateway {
				_ = pool.Put(buf)

				continue
			}

			if D.ShouldHijackDns(dnsAddr, rAddrPort) {
				go func() {
					msg, err := D.RelayDnsPacket(raw)
					if err != nil {
						_ = pool.Put(buf)
						return
					}

					_, _ = stack.UDP().WriteTo(msg, rAddr, lAddr)

					_ = pool.Put(buf)
				}()

				continue
			}

			pkt := &packet{
				local: lAddr,
				data:  raw,
				writeBack: func(b []byte, addr net.Addr) (int, error) {
					return stack.UDP().WriteTo(b, rAddr, lAddr)
				},
				drop: func() {
					_ = pool.Put(buf)
				},
			}

			select {
			case udpIn <- inbound.NewPacket(socks5.ParseAddrToSocksAddr(rAddr), pkt, C.TUN):
			default:
			}
		}

		ipStack.wg.Done()
	}

	ipStack.once.Do(func() {
		ipStack.wg.Add(1)
		go tcp()

		numUDPWorkers := 4
		if num := runtime.GOMAXPROCS(0); num > numUDPWorkers {
			numUDPWorkers = num
		}
		for i := 0; i < numUDPWorkers; i++ {
			ipStack.wg.Add(1)
			go udp()
		}
	})

	return ipStack, nil
}
