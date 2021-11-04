package system

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	D "github.com/Dreamacro/clash/listener/tun/ipstack/commons"
	"github.com/kr328/tun2socket/binding"
	"github.com/kr328/tun2socket/redirect"
)

const defaultDnsReadTimeout = time.Second * 10

func shouldHijackDns(dnsAddr binding.Address, targetAddr binding.Address) bool {
	if targetAddr.Port != 53 {
		return false
	}

	return dnsAddr.IP.Equal(net.IPv4zero) || dnsAddr.IP.Equal(targetAddr.IP)
}

func hijackUDPDns(pkt []byte, ep *binding.Endpoint, sender redirect.UDPSender) {
	go func() {
		answer, err := D.RelayDnsPacket(pkt)
		if err != nil {
			return
		}

		_ = sender(answer, &binding.Endpoint{
			Source: ep.Target,
			Target: ep.Source,
		})
	}()
}

func hijackTCPDns(conn net.Conn) {
	go func() {
		defer func(conn net.Conn) {
			_ = conn.Close()
		}(conn)

		if err := conn.SetReadDeadline(time.Now().Add(defaultDnsReadTimeout)); err != nil {
			return
		}

		for {
			var length uint16
			if binary.Read(conn, binary.BigEndian, &length) != nil {
				return
			}

			data := make([]byte, length)

			_, err := io.ReadFull(conn, data)
			if err != nil {
				return
			}

			rb, err := D.RelayDnsPacket(data)
			if err != nil {
				continue
			}

			if binary.Write(conn, binary.BigEndian, uint16(len(rb))) != nil {
				return
			}

			if _, err = conn.Write(rb); err != nil {
				return
			}
		}
	}()
}
