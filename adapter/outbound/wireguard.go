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
	"time"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/sing"

	wireguard "github.com/MetaCubeX/sing-wireguard"

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
	dialer    *wgDialer
	startOnce sync.Once
}

type WireGuardOption struct {
	BasicOption
	Name         string `proxy:"name"`
	Server       string `proxy:"server"`
	Port         int    `proxy:"port"`
	Ip           string `proxy:"ip"`
	Ipv6         string `proxy:"ipv6,omitempty"`
	PrivateKey   string `proxy:"private-key"`
	PublicKey    string `proxy:"public-key"`
	PreSharedKey string `proxy:"pre-shared-key,omitempty"`
	Reserved     []int  `proxy:"reserved,omitempty"`
	Workers      int    `proxy:"workers,omitempty"`
	MTU          int    `proxy:"mtu,omitempty"`
	UDP          bool   `proxy:"udp,omitempty"`
}

type wgDialer struct {
	options []dialer.Option
}

func (d *wgDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return dialer.DialContext(ctx, network, destination.String(), d.options...)
}

func (d *wgDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return dialer.ListenPacket(ctx, "udp", "", d.options...)
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
		dialer: &wgDialer{},
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
	peerAddr := M.ParseSocksaddr(option.Server)
	peerAddr.Port = uint16(option.Port)
	outbound.bind = wireguard.NewClientBind(context.Background(), outbound.dialer, peerAddr, reserved)
	localPrefixes := make([]netip.Prefix, 0, 2)
	if len(option.Ip) == 0 {
		return nil, E.New("missing local address")
	}
	if !strings.Contains(option.Ip, "/") {
		option.Ip = option.Ip + "/32"
	}
	if prefix, err := netip.ParsePrefix(option.Ip); err == nil {
		localPrefixes = append(localPrefixes, prefix)
	} else {
		return nil, E.Cause(err, "ip address parse error")
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
			sing.Logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...interface{}) {
			sing.Logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	}, option.Workers)
	if debug.Enabled {
		sing.Logger.Trace("created wireguard ipc conf: \n", ipcConf)
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
	w.dialer.options = opts
	var conn net.Conn
	w.startOnce.Do(func() {
		err = w.tunDevice.Start()
	})
	if err != nil {
		return nil, err
	}
	if !metadata.Resolved() {
		addrs, err := resolver.ResolveAllIP(metadata.Host)
		if err != nil {
			return nil, err
		}
		conn, err = N.DialSerial(ctx, w.tunDevice, "tcp", M.ParseSocksaddr(metadata.RemoteAddress()), addrs)
	} else {
		conn, err = w.tunDevice.DialContext(ctx, "tcp", M.ParseSocksaddr(metadata.Pure().RemoteAddress()))
	}
	if err != nil {
		return nil, err
	}
	return NewConn(&wgConn{conn, w}, w), nil
}

func (w *WireGuard) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	w.dialer.options = opts
	var pc net.PacketConn
	w.startOnce.Do(func() {
		err = w.tunDevice.Start()
	})
	if err != nil {
		return nil, err
	}
	if !metadata.Resolved() {
		ip, err := resolver.ResolveIP(metadata.Host)
		if err != nil {
			return nil, errors.New("can't resolve ip")
		}
		metadata.DstIP = ip
	}
	pc, err = w.tunDevice.ListenPacket(ctx, M.ParseSocksaddr(metadata.Pure().RemoteAddress()))
	if err != nil {
		return nil, err
	}
	return newPacketConn(&wgPacketConn{pc, w}, w), nil
}

type wgConn struct {
	conn net.Conn
	wg   *WireGuard
}

func (c *wgConn) Read(b []byte) (n int, err error) {
	defer runtime.KeepAlive(c.wg)
	return c.conn.Read(b)
}

func (c *wgConn) Write(b []byte) (n int, err error) {
	defer runtime.KeepAlive(c.wg)
	return c.conn.Write(b)
}

func (c *wgConn) Close() error {
	defer runtime.KeepAlive(c.wg)
	return c.conn.Close()
}

func (c *wgConn) LocalAddr() net.Addr {
	defer runtime.KeepAlive(c.wg)
	return c.conn.LocalAddr()
}

func (c *wgConn) RemoteAddr() net.Addr {
	defer runtime.KeepAlive(c.wg)
	return c.conn.RemoteAddr()
}

func (c *wgConn) SetDeadline(t time.Time) error {
	defer runtime.KeepAlive(c.wg)
	return c.conn.SetDeadline(t)
}

func (c *wgConn) SetReadDeadline(t time.Time) error {
	defer runtime.KeepAlive(c.wg)
	return c.conn.SetReadDeadline(t)
}

func (c *wgConn) SetWriteDeadline(t time.Time) error {
	defer runtime.KeepAlive(c.wg)
	return c.conn.SetWriteDeadline(t)
}

type wgPacketConn struct {
	pc net.PacketConn
	wg *WireGuard
}

func (pc *wgPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	defer runtime.KeepAlive(pc.wg)
	return pc.pc.ReadFrom(p)
}

func (pc *wgPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	defer runtime.KeepAlive(pc.wg)
	return pc.pc.WriteTo(p, addr)
}

func (pc *wgPacketConn) Close() error {
	defer runtime.KeepAlive(pc.wg)
	return pc.pc.Close()
}

func (pc *wgPacketConn) LocalAddr() net.Addr {
	defer runtime.KeepAlive(pc.wg)
	return pc.pc.LocalAddr()
}

func (pc *wgPacketConn) SetDeadline(t time.Time) error {
	defer runtime.KeepAlive(pc.wg)
	return pc.pc.SetDeadline(t)
}

func (pc *wgPacketConn) SetReadDeadline(t time.Time) error {
	defer runtime.KeepAlive(pc.wg)
	return pc.pc.SetReadDeadline(t)
}

func (pc *wgPacketConn) SetWriteDeadline(t time.Time) error {
	defer runtime.KeepAlive(pc.wg)
	return pc.pc.SetWriteDeadline(t)
}
