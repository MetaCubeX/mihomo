package transport

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/metacubex/quic-go"

	"github.com/metacubex/mihomo/transport/hysteria/conns/faketcp"
	"github.com/metacubex/mihomo/transport/hysteria/conns/udp"
	"github.com/metacubex/mihomo/transport/hysteria/conns/wechat"
	obfsPkg "github.com/metacubex/mihomo/transport/hysteria/obfs"
	"github.com/metacubex/mihomo/transport/hysteria/utils"
)

type ClientTransport struct {
	Dialer *net.Dialer
}

func (ct *ClientTransport) quicPacketConn(proto string, rAddr net.Addr, serverPorts string, obfs obfsPkg.Obfuscator, hopInterval time.Duration, dialer utils.PacketDialer) (net.PacketConn, error) {
	server := rAddr.String()
	if len(proto) == 0 || proto == "udp" {
		conn, err := dialer.ListenPacket(rAddr)
		if err != nil {
			return nil, err
		}
		if obfs != nil {
			if serverPorts != "" {
				return udp.NewObfsUDPHopClientPacketConn(server, serverPorts, hopInterval, obfs, dialer)
			}
			oc := udp.NewObfsUDPConn(conn, obfs)
			return oc, nil
		} else {
			if serverPorts != "" {
				return udp.NewObfsUDPHopClientPacketConn(server, serverPorts, hopInterval, nil, dialer)
			}
			return conn, nil
		}
	} else if proto == "wechat-video" {
		conn, err := dialer.ListenPacket(rAddr)
		if err != nil {
			return nil, err
		}
		if obfs == nil {
			obfs = obfsPkg.NewDummyObfuscator()
		}
		return wechat.NewObfsWeChatUDPConn(conn, obfs), nil
	} else if proto == "faketcp" {
		var conn *faketcp.TCPConn
		conn, err := faketcp.Dial("tcp", server)
		if err != nil {
			return nil, err
		}
		if obfs != nil {
			oc := faketcp.NewObfsFakeTCPConn(conn, obfs)
			return oc, nil
		} else {
			return conn, nil
		}
	} else {
		return nil, fmt.Errorf("unsupported protocol: %s", proto)
	}
}

func (ct *ClientTransport) QUICDial(proto string, server string, serverPorts string, tlsConfig *tls.Config, quicConfig *quic.Config, obfs obfsPkg.Obfuscator, hopInterval time.Duration, dialer utils.PacketDialer) (quic.Connection, error) {
	serverUDPAddr, err := dialer.RemoteAddr(server)
	if err != nil {
		return nil, err
	}

	pktConn, err := ct.quicPacketConn(proto, serverUDPAddr, serverPorts, obfs, hopInterval, dialer)
	if err != nil {
		return nil, err
	}

	transport := quic.Transport{Conn: pktConn}
	transport.SetCreatedConn(true) // auto close conn
	transport.SetSingleUse(true)   // auto close transport
	qs, err := transport.Dial(dialer.Context(), serverUDPAddr, tlsConfig, quicConfig)
	if err != nil {
		_ = pktConn.Close()
		return nil, err
	}
	return qs, nil
}

func (ct *ClientTransport) DialTCP(raddr *net.TCPAddr) (*net.TCPConn, error) {
	conn, err := ct.Dialer.Dial("tcp", raddr.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

func (ct *ClientTransport) ListenUDP() (*net.UDPConn, error) {
	return net.ListenUDP("udp", nil)
}

func isMultiPortAddr(addr string) bool {
	_, portStr, err := net.SplitHostPort(addr)
	if err == nil && (strings.Contains(portStr, ",") || strings.Contains(portStr, "-")) {
		return true
	}
	return false
}
