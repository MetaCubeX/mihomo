package outbound

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/randv2"
	"golang.org/x/crypto/ssh"
)

type Ssh struct {
	*Base

	option *SshOption

	config *ssh.ClientConfig
	client *ssh.Client
	cMutex sync.Mutex
}

type SshOption struct {
	BasicOption
	Name                 string   `proxy:"name"`
	Server               string   `proxy:"server"`
	Port                 int      `proxy:"port"`
	UserName             string   `proxy:"username"`
	Password             string   `proxy:"password,omitempty"`
	PrivateKey           string   `proxy:"private-key,omitempty"`
	PrivateKeyPassphrase string   `proxy:"private-key-passphrase,omitempty"`
	HostKey              []string `proxy:"host-key,omitempty"`
	HostKeyAlgorithms    []string `proxy:"host-key-algorithms,omitempty"`
}

func (s *Ssh) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	client, err := s.connect(ctx, s.addr)
	if err != nil {
		return nil, err
	}
	c, err := client.DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}

	return NewConn(c, s), nil
}

func (s *Ssh) connect(ctx context.Context, addr string) (client *ssh.Client, err error) {
	s.cMutex.Lock()
	defer s.cMutex.Unlock()
	if s.client != nil {
		return s.client, nil
	}
	c, err := s.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	clientConn, chans, reqs, err := ssh.NewClientConn(c, addr, s.config)
	if err != nil {
		return nil, err
	}
	client = ssh.NewClient(clientConn, chans, reqs)

	s.client = client

	go func() {
		_ = client.Wait() // wait shutdown
		_ = client.Close()
		s.cMutex.Lock()
		defer s.cMutex.Unlock()
		if s.client == client {
			s.client = nil
		}
	}()

	return client, nil
}

// ProxyInfo implements C.ProxyAdapter
func (s *Ssh) ProxyInfo() C.ProxyInfo {
	info := s.Base.ProxyInfo()
	info.DialerProxy = s.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (s *Ssh) Close() error {
	s.cMutex.Lock()
	defer s.cMutex.Unlock()
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

func NewSsh(option SshOption) (*Ssh, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	config := ssh.ClientConfig{
		User:              option.UserName,
		HostKeyCallback:   ssh.InsecureIgnoreHostKey(),
		HostKeyAlgorithms: option.HostKeyAlgorithms,
	}

	if option.PrivateKey != "" {
		var b []byte
		var err error
		if strings.Contains(option.PrivateKey, "PRIVATE KEY") {
			b = []byte(option.PrivateKey)
		} else {
			path := C.Path.Resolve(option.PrivateKey)
			if !C.Path.IsSafePath(path) {
				return nil, C.Path.ErrNotSafePath(path)
			}
			b, err = os.ReadFile(path)
			if err != nil {
				return nil, err
			}
		}
		var pKey ssh.Signer
		if option.PrivateKeyPassphrase != "" {
			pKey, err = ssh.ParsePrivateKeyWithPassphrase(b, []byte(option.PrivateKeyPassphrase))
		} else {
			pKey, err = ssh.ParsePrivateKey(b)
		}
		if err != nil {
			return nil, err
		}

		config.Auth = append(config.Auth, ssh.PublicKeys(pKey))
	}

	if option.Password != "" {
		config.Auth = append(config.Auth, ssh.Password(option.Password))
	}

	if len(option.HostKey) != 0 {
		keys := make([]ssh.PublicKey, len(option.HostKey))
		for i, hostKey := range option.HostKey {
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey))
			if err != nil {
				return nil, fmt.Errorf("parse host key :%s", key)
			}
			keys[i] = key
		}
		config.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			serverKey := key.Marshal()
			for _, hostKey := range keys {
				if bytes.Equal(serverKey, hostKey.Marshal()) {
					return nil
				}
			}
			return fmt.Errorf("host key mismatch, server send :%s %s", key.Type(), base64.StdEncoding.EncodeToString(serverKey))
		}
	}

	version := "SSH-2.0-OpenSSH_"
	if randv2.IntN(2) == 0 {
		version += "7." + strconv.Itoa(randv2.IntN(10))
	} else {
		version += "8." + strconv.Itoa(randv2.IntN(9))
	}
	config.ClientVersion = version

	outbound := &Ssh{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.Ssh,
			pdName: option.ProviderName,
			udp:    false,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: option.IPVersion,
		},
		option: &option,
		config: &config,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}
