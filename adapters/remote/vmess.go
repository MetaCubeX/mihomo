package adapters

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Dreamacro/clash/common/vmess"
	C "github.com/Dreamacro/clash/constant"
)

// VmessAdapter is a vmess adapter
type VmessAdapter struct {
	conn net.Conn
}

// Close is used to close connection
func (v *VmessAdapter) Close() {
	v.conn.Close()
}

func (v *VmessAdapter) Conn() net.Conn {
	return v.conn
}

type Vmess struct {
	name   string
	server string
	client *vmess.Client
}

func (ss *Vmess) Name() string {
	return ss.name
}

func (ss *Vmess) Type() C.AdapterType {
	return C.Vmess
}

func (ss *Vmess) Generator(addr *C.Addr) (adapter C.ProxyAdapter, err error) {
	c, err := net.Dial("tcp", ss.server)
	if err != nil {
		return nil, fmt.Errorf("%s connect error", ss.server)
	}
	tcpKeepAlive(c)
	c = ss.client.New(c, parseVmessAddr(addr))
	return &VmessAdapter{conn: c}, err
}

func NewVmess(name string, server string, uuid string, alterID uint16, security string) (*Vmess, error) {
	security = strings.ToLower(security)
	client, err := vmess.NewClient(vmess.Config{
		UUID:     uuid,
		AlterID:  alterID,
		Security: security,
	})
	if err != nil {
		return nil, err
	}
	return &Vmess{
		name:   name,
		server: server,
		client: client,
	}, nil
}

func parseVmessAddr(info *C.Addr) *vmess.DstAddr {
	var addrType byte
	var addr []byte
	switch info.AddrType {
	case C.AtypIPv4:
		addrType = byte(vmess.AtypIPv4)
		addr = make([]byte, net.IPv4len)
		copy(addr[:], info.IP.To4())
	case C.AtypIPv6:
		addrType = byte(vmess.AtypIPv6)
		addr = make([]byte, net.IPv6len)
		copy(addr[:], info.IP.To16())
	case C.AtypDomainName:
		addrType = byte(vmess.AtypDomainName)
		addr = make([]byte, len(info.Host)+1)
		addr[0] = byte(len(info.Host))
		copy(addr[1:], []byte(info.Host))
	}

	port, _ := strconv.Atoi(info.Port)
	return &vmess.DstAddr{
		AddrType: addrType,
		Addr:     addr,
		Port:     uint(port),
	}
}
