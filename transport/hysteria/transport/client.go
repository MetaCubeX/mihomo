package transport

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/Dreamacro/clash/transport/hysteria/conns/faketcp"
	"github.com/Dreamacro/clash/transport/hysteria/conns/udp"
	"github.com/Dreamacro/clash/transport/hysteria/conns/wechat"
	obfsPkg "github.com/Dreamacro/clash/transport/hysteria/obfs"
	"github.com/lucas-clemente/quic-go"
)

type ClientTransport struct {
	Dialer            *net.Dialer
	ResolvePreference ResolvePreference
}

var DefaultClientTransport = &ClientTransport{
	Dialer: &net.Dialer{
		Timeout: 8 * time.Second,
	},
	ResolvePreference: ResolvePreferenceDefault,
}

func (ct *ClientTransport) quicPacketConn(proto string, server string, obfs obfsPkg.Obfuscator) (net.PacketConn, error) {
	if len(proto) == 0 || proto == "udp" {
		conn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, err
		}
		if obfs != nil {
			oc := udp.NewObfsUDPConn(conn, obfs)
			return oc, nil
		} else {
			return conn, nil
		}
	} else if proto == "wechat-video" {
		conn, err := net.ListenUDP("udp", nil)
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

func (ct *ClientTransport) QUICDial(proto string, server string, tlsConfig *tls.Config, quicConfig *quic.Config, obfs obfsPkg.Obfuscator) (quic.Connection, error) {
	serverUDPAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}
	pktConn, err := ct.quicPacketConn(proto, server, obfs)
	if err != nil {
		return nil, err
	}
	qs, err := quic.Dial(pktConn, serverUDPAddr, server, tlsConfig, quicConfig)
	if err != nil {
		_ = pktConn.Close()
		return nil, err
	}
	return qs, nil
}

func (ct *ClientTransport) ResolveIPAddr(address string) (*net.IPAddr, error) {
	return resolveIPAddrWithPreference(address, ct.ResolvePreference)
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
