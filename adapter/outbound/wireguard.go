package outbound

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"

	CN "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"

	wireguard "github.com/metacubex/sing-wireguard"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/debug"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/wireguard-go/device"
)

type WireGuard struct {
	*Base
	bind      *wireguard.ClientBind
	device    *device.Device
	tunDevice wireguard.Device
	dialer    *wgSingDialer
	startOnce sync.Once
	startErr  error
}

type WireGuardOption struct {
	BasicOption
	Name                string  `proxy:"name"`
	Server              string  `proxy:"server"`
	Port                int     `proxy:"port"`
	Ip                  string  `proxy:"ip,omitempty"`
	Ipv6                string  `proxy:"ipv6,omitempty"`
	PrivateKey          string  `proxy:"private-key"`
	PublicKey           string  `proxy:"public-key"`
	PreSharedKey        string  `proxy:"pre-shared-key,omitempty"`
	Reserved            []uint8 `proxy:"reserved,omitempty"`
	Workers             int     `proxy:"workers,omitempty"`
	MTU                 int     `proxy:"mtu,omitempty"`
	UDP                 bool    `proxy:"udp,omitempty"`
	PersistentKeepalive int     `proxy:"persistent-keepalive,omitempty"`
}

type wgSingDialer struct {
	dialer dialer.Dialer
}

var _ N.Dialer = &wgSingDialer{}

func (d *wgSingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, destination.String())
}

func (d *wgSingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.dialer.ListenPacket(ctx, "udp", "", destination.AddrPort())
}

type wgNetDialer struct {
	tunDevice wireguard.Device
}

var _ dialer.NetDialer = &wgNetDialer{}

func (d wgNetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.tunDevice.DialContext(ctx, network, M.ParseSocksaddr(address).Unwrap())
}

func NewWireGuard(option WireGuardOption) (*WireGuard, error) {
	outbound := &WireGuard{
		Base: &Base{
			name:   option.Name,
			addr:   net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:     C.WireGuard,
			udp:    option.UDP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		dialer: &wgSingDialer{dialer: dialer.NewDialer()},
	}
	runtime.SetFinalizer(outbound, closeWireGuard)

	var reserved [3]uint8
	if len(option.Reserved) > 0 {
		if len(option.Reserved) != 3 {
			return nil, E.New("invalid reserved value, required 3 bytes, got ", len(option.Reserved))
		}
		reserved[0] = uint8(option.Reserved[0])
		reserved[1] = uint8(option.Reserved[1])
		reserved[2] = uint8(option.Reserved[2])
	}
	peerAddr := M.ParseSocksaddrHostPort(option.Server, uint16(option.Port))
	outbound.bind = wireguard.NewClientBind(context.Background(), outbound.dialer, true, peerAddr, reserved)
	localPrefixes := make([]netip.Prefix, 0, 2)
	if len(option.Ip) > 0 {
		if !strings.Contains(option.Ip, "/") {
			option.Ip = option.Ip + "/32"
		}
		if prefix, err := netip.ParsePrefix(option.Ip); err == nil {
			localPrefixes = append(localPrefixes, prefix)
		} else {
			return nil, E.Cause(err, "ip address parse error")
		}
	}
	if len(option.Ipv6) > 0 {
		if !strings.Contains(option.Ipv6, "/") {
			option.Ipv6 = option.Ipv6 + "/128"
		}
		if prefix, err := netip.ParsePrefix(option.Ipv6); err == nil {
			localPrefixes = append(localPrefixes, prefix)
		} else {
			return nil, E.Cause(err, "ipv6 address parse error")
		}
	}
	if len(localPrefixes) == 0 {
		return nil, E.New("missing local address")
	}
	var privateKey, peerPublicKey, preSharedKey string
	{
		bytes, err := base64.StdEncoding.DecodeString(option.PrivateKey)
		if err != nil {
			return nil, E.Cause(err, "decode private key")
		}
		privateKey = hex.EncodeToString(bytes)
	}
	{
		bytes, err := base64.StdEncoding.DecodeString(option.PublicKey)
		if err != nil {
			return nil, E.Cause(err, "decode peer public key")
		}
		peerPublicKey = hex.EncodeToString(bytes)
	}
	if option.PreSharedKey != "" {
		bytes, err := base64.StdEncoding.DecodeString(option.PreSharedKey)
		if err != nil {
			return nil, E.Cause(err, "decode pre shared key")
		}
		preSharedKey = hex.EncodeToString(bytes)
	}
	ipcConf := "private_key=" + privateKey
	ipcConf += "\npublic_key=" + peerPublicKey
	ipcConf += "\nendpoint=" + peerAddr.String()
	if preSharedKey != "" {
		ipcConf += "\npreshared_key=" + preSharedKey
	}
	var has4, has6 bool
	for _, address := range localPrefixes {
		if address.Addr().Is4() {
			has4 = true
		} else {
			has6 = true
		}
	}
	if has4 {
		ipcConf += "\nallowed_ip=0.0.0.0/0"
	}
	if has6 {
		ipcConf += "\nallowed_ip=::/0"
	}
	if option.PersistentKeepalive != 0 {
		ipcConf += fmt.Sprintf("\npersistent_keepalive_interval=%d", option.PersistentKeepalive)
	}
	mtu := option.MTU
	if mtu == 0 {
		mtu = 1408
	}
	var err error
	outbound.tunDevice, err = wireguard.NewStackDevice(localPrefixes, uint32(mtu))
	if err != nil {
		return nil, E.Cause(err, "create WireGuard device")
	}
	outbound.device = device.NewDevice(outbound.tunDevice, outbound.bind, &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			log.SingLogger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...interface{}) {
			log.SingLogger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	}, option.Workers)
	if debug.Enabled {
		log.SingLogger.Trace("created wireguard ipc conf: \n", ipcConf)
	}
	err = outbound.device.IpcSet(ipcConf)
	if err != nil {
		return nil, E.Cause(err, "setup wireguard")
	}
	//err = outbound.tunDevice.Start()
	return outbound, nil
}

func closeWireGuard(w *WireGuard) {
	if w.device != nil {
		w.device.Close()
	}
	_ = common.Close(w.tunDevice)
}

func (w *WireGuard) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	options := w.Base.DialOptions(opts...)
	w.dialer.dialer = dialer.NewDialer(options...)
	var conn net.Conn
	w.startOnce.Do(func() {
		w.startErr = w.tunDevice.Start()
	})
	if w.startErr != nil {
		return nil, w.startErr
	}
	if !metadata.Resolved() {
		options = append(options, dialer.WithResolver(resolver.DefaultResolver))
		options = append(options, dialer.WithNetDialer(wgNetDialer{tunDevice: w.tunDevice}))
		conn, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	} else {
		port, _ := strconv.Atoi(metadata.DstPort)
		conn, err = w.tunDevice.DialContext(ctx, "tcp", M.SocksaddrFrom(metadata.DstIP, uint16(port)).Unwrap())
	}
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, E.New("conn is nil")
	}
	return NewConn(CN.NewRefConn(conn, w), w), nil
}

func (w *WireGuard) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	options := w.Base.DialOptions(opts...)
	w.dialer.dialer = dialer.NewDialer(options...)
	var pc net.PacketConn
	w.startOnce.Do(func() {
		w.startErr = w.tunDevice.Start()
	})
	if w.startErr != nil {
		return nil, w.startErr
	}
	if err != nil {
		return nil, err
	}
	if !metadata.Resolved() {
		ip, err := resolver.ResolveIP(ctx, metadata.Host)
		if err != nil {
			return nil, errors.New("can't resolve ip")
		}
		metadata.DstIP = ip
	}
	port, _ := strconv.Atoi(metadata.DstPort)
	pc, err = w.tunDevice.ListenPacket(ctx, M.SocksaddrFrom(metadata.DstIP, uint16(port)).Unwrap())
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, E.New("packetConn is nil")
	}
	return newPacketConn(CN.NewRefPacketConn(pc, w), w), nil
}
