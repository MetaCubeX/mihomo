package mixed

import (
	"bytes"
	"crypto/tls"
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/listener/socks"
	"net"
	"strconv"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"
	proxyproto "github.com/pires/go-proxyproto"
)

const recordTypeHandshake = 0x16

var sshPrefix = []byte("SSH-")
var SynDrive = []byte{0x25, 0x52, 0x18, 0x14}

var tlsConfig *tls.Config

func NewTls(addr string, wanInput *inbound.WanInput, tunnel C.Tunnel) (*Listener, error) {

	if wanInput.TlsProxy != nil {
		if wanInput.TlsProxy.Cert != "" && wanInput.TlsProxy.Key != "" {
			certFile := wanInput.TlsProxy.Cert
			keyFile := wanInput.TlsProxy.Key
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, err
			}

			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
			}

		}
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	proxyListener := &proxyproto.Listener{Listener: l}

	ml := &Listener{
		listener: proxyListener,
		addr:     addr,
		// cache:    cache.New(cache.WithAge(30)),
	}
	go func() {
		for {
			c, err := ml.listener.Accept()

			// log.Warnln("local %s, remote %s", c.LocalAddr().String(), c.RemoteAddr().String())
			if err != nil {
				if ml.closed {
					break
				}
				continue
			}
			tcpcon, ok := c.(*proxyproto.Conn).TCPConn()
			if ok {
				N.TCPKeepAlive(tcpcon)
			}

			myConn := NewMyConn(c)
			head, err := myConn.Peek(4)
			if err != nil {
				c.Close()
				continue
			}

			if head[0] == recordTypeHandshake && tlsConfig != nil {
				go handleConnTls(myConn, wanInput.TlsProxy, tunnel)
			} else if bytes.Equal(head, sshPrefix) {
				go handleSSh(myConn, wanInput.SshProxy)
			} else if bytes.Equal(head, SynDrive) {
				go handleSynDrive(myConn, wanInput.Syndrive)
			} else {
				myConn.Close()
			}

		}
	}()

	return ml, nil
}

func handleSynDrive(conn net.Conn, syndrive *inbound.SynDrive) {
	defer conn.Close()
	if syndrive != nil {
		conn2target(conn, syndrive.Target, false, "syn")
	}

}

func handleSSh(conn net.Conn, sshProxy *inbound.SSHProxy) {
	defer conn.Close()
	if sshProxy != nil {
		conn2target(conn, sshProxy.Target, sshProxy.ProxyProto, "ssh")
	} else {
		sshServer.HandleConn(conn)
	}

}

func handleConnTls(conn net.Conn, tlsProxy *inbound.TLSProxy, tunnel C.Tunnel) {
	tlsConn := tls.Server(conn, tlsConfig)
	err := tlsConn.Handshake()
	if err != nil {
		tlsConn.Close()
		return
	}

	myConn := NewMyConn(tlsConn)
	head, err := myConn.Peek(1)
	if err != nil {
		myConn.Close()
		return
	}
	if head[0] == socks5.Version {
		socks.HandleSocks5(myConn, tunnel)
	} else {
		defer myConn.Close()

		connectionState := tlsConn.ConnectionState()
		domain := connectionState.ServerName

		target, ok := tlsProxy.TlsTargets[domain]
		if ok {
			conn2target(myConn, target.Target, target.ProxyProto, "tls")
		} else {
			target, ok := tlsProxy.TlsTargets["all"]
			if ok {
				conn2target(myConn, target.Target, target.ProxyProto, "tls")
			}
		}
	}
}

func conn2target(conn net.Conn, target string, useProxyProto bool, protoType string) {
	cc, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		log.Errorln("%s -> %v", conn.RemoteAddr().String(), err)
		return
	}
	defer cc.Close()
	if useProxyProto {
		shost, sport, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			log.Errorln("%s -> %v", conn.RemoteAddr().String(), err)
			return
		}
		siport, err := strconv.Atoi(sport)
		if err != nil {
			log.Errorln("%s -> %v", conn.RemoteAddr().String(), err)
			return
		}
		lhost, lport, err := net.SplitHostPort(conn.LocalAddr().String())
		if err != nil {
			log.Errorln("%s -> %v", conn.RemoteAddr().String(), err)
			return
		}
		liport, err := strconv.Atoi(lport)
		if err != nil {
			log.Errorln("%s -> %v", conn.RemoteAddr().String(), err)
			return
		}

		remoteIp := net.ParseIP(shost)
		tranPro := proxyproto.TCPv6
		if remoteIp.To4() != nil {
			tranPro = proxyproto.TCPv4
		}
		header := &proxyproto.Header{
			Version:           1,
			Command:           proxyproto.PROXY,
			TransportProtocol: tranPro,
			SourceAddr: &net.TCPAddr{
				IP:   remoteIp,
				Port: siport,
			},
			DestinationAddr: &net.TCPAddr{
				IP:   net.ParseIP(lhost),
				Port: liport,
			},
		}

		_, err = header.WriteTo(cc)
		if err != nil {
			log.Errorln("%s -> %v", conn.RemoteAddr().String(), err)
			return
		}
	}
	log.Infoln("%s %s -> %v", protoType, conn.RemoteAddr().String(), target)
	N.Relay(conn, cc)
}
