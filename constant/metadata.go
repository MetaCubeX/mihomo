package constant

import (
	"encoding/json"
	"net"
	"strconv"
)

// Socks addr type
const (
	AtypIPv4       = 1
	AtypDomainName = 3
	AtypIPv6       = 4

	TCP NetWork = iota
	UDP

	HTTP Type = iota
	HTTPCONNECT
	SOCKS4
	SOCKS5
	REDIR
	TPROXY
)

type NetWork int

func (n NetWork) String() string {
	if n == TCP {
		return "tcp"
	}
	return "udp"
}

func (n NetWork) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.String())
}

type Type int

func (t Type) String() string {
	switch t {
	case HTTP:
		return "HTTP"
	case HTTPCONNECT:
		return "HTTP Connect"
	case SOCKS4:
		return "Socks4"
	case SOCKS5:
		return "Socks5"
	case REDIR:
		return "Redir"
	case TPROXY:
		return "TProxy"
	default:
		return "Unknown"
	}
}

func (t Type) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// Metadata is used to store connection address
type Metadata struct {
	NetWork     NetWork `json:"network"`
	Type        Type    `json:"type"`
	SrcIP       net.IP  `json:"sourceIP"`
	DstIP       net.IP  `json:"destinationIP"`
	SrcPort     string  `json:"sourcePort"`
	DstPort     string  `json:"destinationPort"`
	AddrType    int     `json:"-"`
	Host        string  `json:"host"`
	DNSMode     DNSMode `json:"dnsMode"`
	ProcessPath string  `json:"processPath"`
}

func (m *Metadata) RemoteAddress() string {
	return net.JoinHostPort(m.String(), m.DstPort)
}

func (m *Metadata) SourceAddress() string {
	return net.JoinHostPort(m.SrcIP.String(), m.SrcPort)
}

func (m *Metadata) Resolved() bool {
	return m.DstIP != nil
}

// Pure is used to solve unexpected behavior
// when dialing proxy connection in DNSMapping mode.
func (m *Metadata) Pure() *Metadata {
	if m.DNSMode == DNSMapping && m.DstIP != nil {
		copy := *m
		copy.Host = ""
		if copy.DstIP.To4() != nil {
			copy.AddrType = AtypIPv4
		} else {
			copy.AddrType = AtypIPv6
		}
		return &copy
	}

	return m
}

func (m *Metadata) UDPAddr() *net.UDPAddr {
	if m.NetWork != UDP || m.DstIP == nil {
		return nil
	}
	port, _ := strconv.ParseUint(m.DstPort, 10, 16)
	return &net.UDPAddr{
		IP:   m.DstIP,
		Port: int(port),
	}
}

func (m *Metadata) String() string {
	if m.Host != "" {
		return m.Host
	} else if m.DstIP != nil {
		return m.DstIP.String()
	} else {
		return "<nil>"
	}
}

func (m *Metadata) Valid() bool {
	return m.Host != "" || m.DstIP != nil
}
