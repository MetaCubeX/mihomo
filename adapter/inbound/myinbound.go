package inbound

import (
	"fmt"
	C "github.com/metacubex/mihomo/constant"
	gossh "golang.org/x/crypto/ssh"
	"net"
	"net/netip"
	"time"
)

type LocalForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}

type MySSHConn struct {
	gossh.Channel
	LocalAddr_  net.Addr
	RemoteAddr_ net.Addr
}

var channelCloseBytes = [1]byte{97}

func (m *MySSHConn) Close() error {
	//m.Write(channelCloseBytes[:])
	return m.Channel.Close()
}

func (m *MySSHConn) LocalAddr() net.Addr {
	return m.LocalAddr_
}

func (m *MySSHConn) RemoteAddr() net.Addr {
	return m.RemoteAddr_
}

func (m *MySSHConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *MySSHConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *MySSHConn) SetWriteDeadline(t time.Time) error {
	return nil
}
func NewSSH(data *LocalForwardChannelData, conn net.Conn, source C.Type) *C.Metadata {
	metadata := &C.Metadata{}
	metadata.NetWork = C.TCP
	metadata.Host = data.DestAddr
	metadata.DstPort = uint16(data.DestPort)

	if ip := net.ParseIP(metadata.Host); ip != nil {
		addr, _ := netip.AddrFromSlice([]byte(ip))
		metadata.DstIP = addr
	}

	metadata.Type = source
	if ip, port, err := parseAddr(conn.RemoteAddr()); err == nil {
		addr, _ := netip.AddrFromSlice([]byte(ip))
		metadata.SrcIP = addr
		metadata.SrcPort = uint16(port)
	}

	return metadata
}

type TLSProxy struct {
	Cert        string                `yaml:"cert"`
	Key         string                `yaml:"key"`
	Socks5Proxy *Socks5Proxy          `yaml:"socks5"`
	TlsTargets  map[string]*TlsTarget `yaml:"proxy"`
}

type TlsTarget struct {
	ProxyProto bool   `yaml:"proxyproto"`
	Target     string `yaml:"target"`
}

type Socks5Proxy struct {
}

type SSHProxy struct {
	ProxyProto bool   `yaml:"proxyproto"`
	Target     string `yaml:"target"`
}

type SynDrive struct {
	Target string `yaml:"target"`
}

type WanInput struct {
	Port           int       `yaml:"port"`
	Authentication []string  `yaml:"authentication"`
	SshProxy       *SSHProxy `yaml:"ssh"`
	TlsProxy       *TLSProxy `yaml:"tls"`
	Syndrive       *SynDrive `yaml:"syn-drive"`
}

func parseAddr(addr net.Addr) (net.IP, int, error) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP, a.Port, nil
	case *net.UDPAddr:
		return a.IP, a.Port, nil
	default:
		return nil, 0, fmt.Errorf("unknown address type %s", addr.String())
	}
}
