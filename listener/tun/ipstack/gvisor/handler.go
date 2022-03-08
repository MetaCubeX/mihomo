package gvisor

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/pool"
	C "github.com/Dreamacro/clash/constant"
	D "github.com/Dreamacro/clash/listener/tun/ipstack/commons"
	"github.com/Dreamacro/clash/listener/tun/ipstack/gvisor/adapter"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/transport/socks5"
)

var _ adapter.Handler = (*GVHandler)(nil)

type GVHandler struct {
	DNSAdds []net.IP

	TCPIn chan<- C.ConnContext
	UDPIn chan<- *inbound.PacketAdapter
}

func (gh *GVHandler) HandleTCPConn(tunConn adapter.TCPConn) {
	id := tunConn.ID()

	rAddr := &net.UDPAddr{
		IP:   net.IP(id.LocalAddress),
		Port: int(id.LocalPort),
		Zone: "",
	}

	if D.ShouldHijackDns(gh.DNSAdds, rAddr.IP, rAddr.Port) {
		go func() {
			log.Debugln("[TUN] hijack dns tcp: %s", rAddr.String())

			defer tunConn.Close()

			buf := pool.Get(pool.UDPBufferSize)
			defer pool.Put(buf)

			for {
				tunConn.SetReadDeadline(time.Now().Add(D.DefaultDnsReadTimeout))

				length := uint16(0)
				if err := binary.Read(tunConn, binary.BigEndian, &length); err != nil {
					return
				}

				if int(length) > len(buf) {
					return
				}

				n, err := tunConn.Read(buf[:length])
				if err != nil {
					return
				}

				msg, err := D.RelayDnsPacket(buf[:n])
				if err != nil {
					return
				}

				_, _ = tunConn.Write(msg)
			}
		}()

		return
	}

	gh.TCPIn <- inbound.NewSocket(socks5.ParseAddrToSocksAddr(rAddr), tunConn, C.TUN)
}

func (gh *GVHandler) HandleUDPConn(tunConn adapter.UDPConn) {
	id := tunConn.ID()

	rAddr := &net.UDPAddr{
		IP:   net.IP(id.LocalAddress),
		Port: int(id.LocalPort),
		Zone: "",
	}

	target := socks5.ParseAddrToSocksAddr(rAddr)

	go func() {
		for {
			buf := pool.Get(pool.UDPBufferSize)

			n, addr, err := tunConn.ReadFrom(buf)
			if err != nil {
				pool.Put(buf)
				return
			}

			payload := buf[:n]

			if D.ShouldHijackDns(gh.DNSAdds, rAddr.IP, rAddr.Port) {
				go func() {
					defer pool.Put(buf)

					msg, err1 := D.RelayDnsPacket(payload)
					if err1 != nil {
						return
					}

					_, _ = tunConn.WriteTo(msg, addr)

					log.Debugln("[TUN] hijack dns udp: %s", rAddr.String())
				}()

				continue
			}

			gvPacket := &packet{
				pc:      tunConn,
				rAddr:   addr,
				payload: payload,
			}

			gh.UDPIn <- inbound.NewPacket(target, gvPacket, C.TUN)
		}
	}()
}
