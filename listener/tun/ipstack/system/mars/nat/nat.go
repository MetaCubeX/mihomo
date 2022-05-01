package nat

import (
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"net/netip"

	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/listener/tun/ipstack/system/mars/tcpip"
)

func Start(device io.ReadWriter, gateway, portal, broadcast netip.Addr) (*TCP, *UDP, error) {
	if !portal.Is4() || !gateway.Is4() {
		return nil, nil, net.InvalidAddrError("only ipv4 supported")
	}

	listener, err := net.ListenTCP("tcp4", nil)
	if err != nil {
		return nil, nil, err
	}

	tab := newTable()
	udp := &UDP{
		device: device,
		buf:    [pool.UDPBufferSize]byte{},
	}
	tcp := &TCP{
		listener: listener,
		portal:   portal,
		table:    tab,
	}

	gatewayPort := uint16(listener.Addr().(*net.TCPAddr).Port)

	go func() {
		defer func() {
			_ = tcp.Close()
			_ = udp.Close()
		}()

		buf := make([]byte, pool.RelayBufferSize)

		for {
			n, err := device.Read(buf)
			if err != nil {
				log.Errorf("system error:%s", err.Error())
				return
			}

			raw := buf[:n]

			var (
				ipVersion int
				ip        tcpip.IP
			)

			ipVersion = tcpip.IPVersion(raw)

			switch ipVersion {
			case tcpip.IPv4Version:
				ipv4 := tcpip.IPv4Packet(raw)
				if !ipv4.Valid() {
					continue
				}

				if ipv4.TimeToLive() == 0x00 {
					continue
				}

				if ipv4.Flags()&tcpip.FlagMoreFragment != 0 {
					continue
				}

				if ipv4.FragmentOffset() != 0 {
					continue
				}

				ip = ipv4
			case tcpip.IPv6Version:
				ipv6 := tcpip.IPv6Packet(raw)
				if !ipv6.Valid() {
					continue
				}

				if ipv6.HopLimit() == 0x00 {
					continue
				}

				ip = ipv6
			default:
				continue
			}

			destinationIP := ip.DestinationIP()

			if !destinationIP.IsGlobalUnicast() || destinationIP == broadcast {
				continue
			}

			switch ip.Protocol() {
			case tcpip.TCP:
				t := tcpip.TCPPacket(ip.Payload())
				if !t.Valid() {
					continue
				}

				if destinationIP == portal {
					if ip.SourceIP() == gateway && t.SourcePort() == gatewayPort {
						tup := tab.tupleOf(t.DestinationPort())
						if tup == zeroTuple {
							continue
						}

						ip.SetSourceIP(tup.DestinationAddr.Addr())
						t.SetSourcePort(tup.DestinationAddr.Port())
						ip.SetDestinationIP(tup.SourceAddr.Addr())
						t.SetDestinationPort(tup.SourceAddr.Port())

						ip.DecTimeToLive()
						ip.ResetChecksum()
						t.ResetChecksum(ip.PseudoSum())

						_, _ = device.Write(raw)
					}
				} else {
					tup := tuple{
						SourceAddr:      netip.AddrPortFrom(ip.SourceIP(), t.SourcePort()),
						DestinationAddr: netip.AddrPortFrom(destinationIP, t.DestinationPort()),
					}

					port := tab.portOf(tup)
					if port == 0 {
						if t.Flags() != tcpip.TCPSyn {
							continue
						}

						port = tab.newConn(tup)
					}

					ip.SetSourceIP(portal)
					ip.SetDestinationIP(gateway)
					t.SetSourcePort(port)
					t.SetDestinationPort(gatewayPort)

					ip.ResetChecksum()
					t.ResetChecksum(ip.PseudoSum())

					_, _ = device.Write(raw)
				}
			case tcpip.UDP:
				u := tcpip.UDPPacket(ip.Payload())
				if !u.Valid() {
					continue
				}

				udp.handleUDPPacket(ip, u)
			case tcpip.ICMP:
				i := tcpip.ICMPPacket(ip.Payload())

				if i.Type() != tcpip.ICMPTypePingRequest || i.Code() != 0 {
					continue
				}

				i.SetType(tcpip.ICMPTypePingResponse)

				ip.SetDestinationIP(ip.SourceIP())
				ip.SetSourceIP(destinationIP)

				ip.ResetChecksum()
				i.ResetChecksum()

				_, _ = device.Write(raw)
			case tcpip.ICMPv6:
				i := tcpip.ICMPv6Packet(ip.Payload())

				if i.Type() != tcpip.ICMPv6EchoRequest || i.Code() != 0 {
					continue
				}

				i.SetType(tcpip.ICMPv6EchoReply)

				ip.SetDestinationIP(ip.SourceIP())
				ip.SetSourceIP(destinationIP)

				ip.ResetChecksum()
				i.ResetChecksum(ip.PseudoSum())

				_, _ = device.Write(raw)
			}
		}
	}()

	return tcp, udp, nil
}
