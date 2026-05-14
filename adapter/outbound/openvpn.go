package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"
	ovpn "github.com/metacubex/mihomo/transport/openvpn"

	wireguard "github.com/metacubex/sing-wireguard"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
)

type OpenVPN struct {
	*Base
	option *OpenVPNOption
	config *ovpn.ClientConfig

	tunDevice wireguard.Device
	client    *ovpn.Client
	resolver  resolver.Resolver
	dns       []dns.NameServer

	runCtx    context.Context
	runCancel context.CancelFunc
	runMutex  sync.Mutex
	running   bool
}

type OpenVPNOption struct {
	BasicOption
	Name     string `proxy:"name"`
	Server   string `proxy:"server"`
	Port     int    `proxy:"port"`
	Proto    string `proxy:"proto,omitempty"`
	Dev      string `proxy:"dev,omitempty"`
	Cipher   string `proxy:"cipher,omitempty"`
	Auth     string `proxy:"auth,omitempty"`
	CA       string `proxy:"ca"`
	Cert     string `proxy:"cert,omitempty"`
	Key      string `proxy:"key,omitempty"`
	TLSCrypt string `proxy:"tls-crypt"`
	Username string `proxy:"username,omitempty"`
	Password string `proxy:"password,omitempty"`
	MTU      int    `proxy:"mtu,omitempty"`
	UDP      bool   `proxy:"udp,omitempty"`

	RemoteDnsResolve bool     `proxy:"remote-dns-resolve,omitempty"`
	Dns              []string `proxy:"dns,omitempty"`
}

func NewOpenVPN(option OpenVPNOption) (*OpenVPN, error) {
	cfg := &ovpn.ClientConfig{
		RemoteHost: option.Server,
		RemotePort: uint16(option.Port),
		Proto:      option.Proto,
		Dev:        option.Dev,
		Cipher:     option.Cipher,
		Auth:       option.Auth,
		CA:         []byte(option.CA),
		Cert:       []byte(option.Cert),
		Key:        []byte(option.Key),
		TLSCrypt:   []byte(option.TLSCrypt),
		Username:   option.Username,
		Password:   option.Password,
	}
	if err := cfg.Prepare(); err != nil {
		return nil, err
	}

	outbound := &OpenVPN{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         cfg.RemoteAddress(),
			Type:         C.OpenVPN,
			ProviderName: option.ProviderName,
			UDP:          true,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
		config: cfg,
	}
	if option.RemoteDnsResolve && len(option.Dns) > 0 {
		nss, err := dns.ParseNameServer(option.Dns)
		if err != nil {
			return nil, err
		}
		outbound.dns = nss
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	outbound.runCtx, outbound.runCancel = context.WithCancel(context.Background())
	return outbound, nil
}

func (o *OpenVPN) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if err = o.run(ctx); err != nil {
		return nil, err
	}
	var conn net.Conn
	if !metadata.Resolved() || o.resolver != nil {
		r := resolver.DefaultResolver
		if o.resolver != nil {
			r = o.resolver
		}
		options := o.DialOptions()
		options = append(options, dialer.WithResolver(r))
		options = append(options, dialer.WithNetDialer(wgNetDialer{tunDevice: o.tunDevice}))
		conn, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	} else {
		conn, err = o.tunDevice.DialContext(ctx, "tcp", M.SocksaddrFrom(metadata.DstIP, metadata.DstPort).Unwrap())
	}
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, E.New("conn is nil")
	}
	return NewConn(conn, o), nil
}

func (o *OpenVPN) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	var pc net.PacketConn
	if err = o.run(ctx); err != nil {
		return nil, err
	}
	if err = o.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	pc, err = o.tunDevice.ListenPacket(ctx, M.SocksaddrFrom(metadata.DstIP, metadata.DstPort).Unwrap())
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, errors.New("packetConn is nil")
	}
	return newPacketConn(pc, o), nil
}

func (o *OpenVPN) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if (!metadata.Resolved() || o.resolver != nil) && metadata.Host != "" {
		r := resolver.DefaultResolver
		if o.resolver != nil {
			r = o.resolver
		}
		ip, err := resolver.ResolveIPWithResolver(ctx, metadata.Host, r)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

func (o *OpenVPN) ProxyInfo() C.ProxyInfo {
	info := o.Base.ProxyInfo()
	info.DialerProxy = o.option.DialerProxy
	return info
}

func (o *OpenVPN) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

func (o *OpenVPN) Close() error {
	if o.runCancel != nil {
		o.runCancel()
	}
	o.runMutex.Lock()
	client := o.client
	tunDevice := o.tunDevice
	o.client = nil
	o.tunDevice = nil
	o.running = false
	o.runMutex.Unlock()

	if client != nil {
		_ = client.Close()
	}
	if tunDevice != nil {
		return tunDevice.Close()
	}
	return nil
}

func (o *OpenVPN) run(ctx context.Context) error {
	o.runMutex.Lock()
	defer o.runMutex.Unlock()
	if o.running {
		return nil
	}
	if o.runCtx.Err() != nil {
		return o.runCtx.Err()
	}

	packetIO, err := o.openPacketIO(ctx)
	if err != nil {
		return err
	}
	client, err := ovpn.NewClient(o.config, packetIO)
	if err != nil {
		_ = packetIO.Close()
		return err
	}
	push, err := client.Handshake(ctx)
	if err != nil {
		_ = client.Close()
		return err
	}
	log.Debugln("[OpenVPN](%s) handshake complete: prefixes=%v peer-id=%d dns=%v redirect=%t block-ipv6=%t", o.name, push.Prefixes, push.PeerID, push.DNS, push.Redirect, push.BlockIPv6)

	mtu := o.option.MTU
	if mtu == 0 {
		mtu = 1500
	}
	tunDevice, err := wireguard.NewStackDevice(push.Prefixes, uint32(mtu))
	if err != nil {
		_ = client.Close()
		return E.Cause(err, "create OpenVPN stack device")
	}
	if err := tunDevice.Start(); err != nil {
		_ = client.Close()
		_ = tunDevice.Close()
		return err
	}
	o.client = client
	o.tunDevice = tunDevice
	o.running = true
	if o.option.RemoteDnsResolve && len(o.dns) > 0 && o.resolver == nil {
		nss := append([]dns.NameServer(nil), o.dns...)
		for i := range nss {
			nss[i].ProxyAdapter = o
		}
		o.resolver = dns.NewResolver(dns.Config{
			Main: nss,
			IPv6: openVPNPrefixesHas6(push.Prefixes),
		})
	}
	o.startPacketLoops()
	return nil
}

func openVPNPrefixesHas6(prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if !prefix.Addr().Unmap().Is4() {
			return true
		}
	}
	return false
}

func (o *OpenVPN) openPacketIO(ctx context.Context) (ovpn.PacketIO, error) {
	switch o.config.Proto {
	case ovpn.ProtoUDP:
		conn, err := o.dialer.DialContext(ctx, "udp", o.addr)
		if err != nil {
			return nil, err
		}
		return ovpn.NewDatagramPacketIO(conn), nil
	case ovpn.ProtoTCP:
		conn, err := o.dialer.DialContext(ctx, "tcp", o.addr)
		if err != nil {
			return nil, err
		}
		return ovpn.NewTCPPacketIO(conn), nil
	default:
		return nil, fmt.Errorf("unsupported openvpn proto %q", o.config.Proto)
	}
}

func (o *OpenVPN) startPacketLoops() {
	runCtx, runCancel := context.WithCancel(o.runCtx)
	client := o.client
	tunDevice := o.tunDevice
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			runCancel()
			_ = client.Close()
			_ = tunDevice.Close()
			o.runMutex.Lock()
			if o.client == client {
				o.client = nil
				o.tunDevice = nil
				o.running = false
			}
			o.runMutex.Unlock()
		})
	}
	go func() {
		defer stop()
		buf := make([]byte, 64*1024)
		bufs := [][]byte{buf}
		sizes := []int{0}
		for runCtx.Err() == nil {
			_, err := tunDevice.Read(bufs, sizes, 0)
			if err != nil {
				if runCtx.Err() == nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
					log.Errorln("[OpenVPN](%s) error reading from stack device: %v", o.name, err)
				}
				return
			}
			if err := client.WriteIPPacket(runCtx, buf[:sizes[0]]); err != nil {
				if !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
					log.Warnln("[OpenVPN](%s) error writing packet to OpenVPN link: %v", o.name, err)
				}
				return
			}
		}
	}()

	go func() {
		defer stop()
		for runCtx.Err() == nil {
			packet, err := client.ReadIPPacket(runCtx)
			if err != nil {
				if runCtx.Err() == nil && (errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed)) {
					log.Warnln("[OpenVPN](%s) OpenVPN link closed while reading packet: %v", o.name, err)
				} else if !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
					log.Warnln("[OpenVPN](%s) error reading packet from OpenVPN link: %v", o.name, err)
				}
				return
			}
			if _, err := tunDevice.Write([][]byte{packet}, 0); err != nil {
				if !errors.Is(err, net.ErrClosed) {
					log.Errorln("[OpenVPN](%s) error writing to stack device: %v", o.name, err)
				}
				return
			}
		}
	}()
}
