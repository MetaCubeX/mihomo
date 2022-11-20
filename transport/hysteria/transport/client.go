package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/Dreamacro/clash/transport/hysteria/conns/faketcp"
	"github.com/Dreamacro/clash/transport/hysteria/conns/udp"
	"github.com/Dreamacro/clash/transport/hysteria/conns/wechat"
	obfsPkg "github.com/Dreamacro/clash/transport/hysteria/obfs"
	"github.com/lucas-clemente/quic-go"
	"net"
	"strings"
	"time"
)

type ClientTransport struct {
	Dialer *net.Dialer
}

func (ct *ClientTransport) quicPacketConn(proto string, server string, obfs obfsPkg.Obfuscator, hopInterval time.Duration, dialer PacketDialer) (net.PacketConn, net.Addr, error) {
	if len(proto) == 0 || proto == "udp" {
		conn, err := dialer.ListenPacket()
		if err != nil {
			return nil, nil, err
		}
		if obfs != nil {
			if isMultiPortAddr(server) {
				return udp.NewObfsUDPHopClientPacketConn(server, hopInterval, obfs)
			}
			oc := udp.NewObfsUDPConn(conn, obfs)
			return oc, nil, nil
		} else {
			if isMultiPortAddr(server) {
				return udp.NewObfsUDPHopClientPacketConn(server, hopInterval, nil)
			}
			return conn, nil, nil
		}
	} else if proto == "wechat-video" {
		conn, err := dialer.ListenPacket()
		if err != nil {
			return nil, nil, err
		}
		if obfs == nil {
			obfs = obfsPkg.NewDummyObfuscator()
		}
		return wechat.NewObfsWeChatUDPConn(conn, obfs), nil, nil
	} else if proto == "faketcp" {
		var conn *faketcp.TCPConn
		conn, err := faketcp.Dial("tcp", server)
		if err != nil {
			return nil, nil, err
		}
		if obfs != nil {
			oc := faketcp.NewObfsFakeTCPConn(conn, obfs)
			return oc, nil, nil
		} else {
			return conn, nil, nil
		}
	} else {
		return nil, nil, fmt.Errorf("unsupported protocol: %s", proto)
	}
}

type PacketDialer interface {
	ListenPacket() (net.PacketConn, error)
	Context() context.Context
	RemoteAddr(host string) (net.Addr, error)
}

func (ct *ClientTransport) QUICDial(proto string, server string, tlsConfig *tls.Config, quicConfig *quic.Config, obfs obfsPkg.Obfuscator, hopInterval time.Duration, dialer PacketDialer) (quic.Connection, error) {
	serverUDPAddr, err := dialer.RemoteAddr(server)
	if err != nil {
		return nil, err
	}

	pktConn, _, err := ct.quicPacketConn(proto, serverUDPAddr.String(), obfs, hopInterval, dialer)
	if err != nil {
		return nil, err
	}

	qs, err := quic.DialContext(dialer.Context(), pktConn, serverUDPAddr, server, tlsConfig, quicConfig)
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
