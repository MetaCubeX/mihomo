package outbound

import (
	"context"
	"net"
	"os"
	"runtime"
	"strconv"

	CN "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"golang.org/x/crypto/ssh"
)

type Ssh struct {
	*Base

	option *SshOption
	client *ssh.Client
}

type SshOption struct {
	BasicOption
	Name       string `proxy:"name"`
	Server     string `proxy:"server"`
	Port       int    `proxy:"port"`
	UserName   string `proxy:"username"`
	Password   string `proxy:"password,omitempty"`
	PrivateKey string `proxy:"privateKey,omitempty"`
}

func (h *Ssh) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	c, err := h.client.Dial("tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return NewConn(CN.NewRefConn(c, h), h), nil
}

func closeSsh(h *Ssh) {
	if h.client != nil {
		_ = h.client.Close()
	}
}

func NewSsh(option SshOption) (*Ssh, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	config := ssh.ClientConfig{
		User: option.UserName,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	if option.Password == "" {

		b, err := os.ReadFile(option.PrivateKey)
		if err != nil {
			return nil, err
		}
		pKey, err := ssh.ParsePrivateKey(b)
		if err != nil {
			return nil, err
		}

		config.Auth = []ssh.AuthMethod{
			ssh.PublicKeys(pKey),
		}
	} else {
		config.Auth = []ssh.AuthMethod{
			ssh.Password(option.Password),
		}
	}

	client, err := ssh.Dial("tcp", addr, &config)
	if err != nil {
		return nil, err
	}

	outbound := &Ssh{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.Ssh,
			udp:    true,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		option: &option,
		client: client,
	}
	runtime.SetFinalizer(outbound, closeSsh)

	return outbound, nil
}
