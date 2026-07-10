//go:build with_gvisor && !no_tailscale && linux

package outbound

import (
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/log"

	singtun "github.com/metacubex/sing-tun"
	tstun "github.com/metacubex/tailscale-wireguard-go/tun"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

const (
	tailscaleKernelHostForwardDefaultMTU       = 1280
	tailscaleKernelHostForwardMaxDeviceNameLen = 15
)

var tailscaleKernelHostForwardDefaultRoutes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

type tailscaleKernelHostForwarder struct {
	deviceName string
	mtu        uint32
	tun        *tailscaleKernelTUN
	routes     []netip.Prefix

	mu             sync.Mutex
	configured     bool
	addresses      []netip.Prefix
	ownedAddresses []netip.Prefix
	ownedRoutes    []netip.Prefix
}

func newTailscaleKernelHostForwarder(name string, option TailscaleHostForwardOption) (*tailscaleKernelHostForwarder, error) {
	deviceName, err := tailscaleKernelHostForwardDeviceName(name, option.Device)
	if err != nil {
		return nil, err
	}
	mtu := option.MTU
	if mtu == 0 {
		mtu = tailscaleKernelHostForwardDefaultMTU
	}
	if mtu < 1280 {
		return nil, fmt.Errorf("tailscale kernel host-forward mtu must be at least 1280: %d", mtu)
	}

	k := &tailscaleKernelHostForwarder{
		deviceName: deviceName,
		mtu:        mtu,
		routes:     append([]netip.Prefix{}, tailscaleKernelHostForwardDefaultRoutes...),
	}
	tun, err := newTailscaleKernelTUN(deviceName, mtu, k.cleanup)
	if err != nil {
		return nil, fmt.Errorf("create tailscale kernel host-forward tun %s: %w", deviceName, err)
	}
	k.tun = tun
	return k, nil
}

func tailscaleKernelHostForwardDeviceName(proxyName, configured string) (string, error) {
	deviceName := strings.TrimSpace(configured)
	if deviceName == "" {
		h := fnv.New32a()
		_, _ = h.Write([]byte(proxyName))
		deviceName = fmt.Sprintf("mts%08x", h.Sum32())
	}
	if len([]byte(deviceName)) > tailscaleKernelHostForwardMaxDeviceNameLen {
		return "", fmt.Errorf("tailscale kernel host-forward device name %q exceeds %d bytes", deviceName, tailscaleKernelHostForwardMaxDeviceNameLen)
	}
	if strings.ContainsAny(deviceName, " \t\r\n/") {
		return "", fmt.Errorf("tailscale kernel host-forward device name %q contains whitespace or slash", deviceName)
	}
	return deviceName, nil
}

func (k *tailscaleKernelHostForwarder) Device() tstun.Device {
	return k.tun
}

func (k *tailscaleKernelHostForwarder) Name() string {
	return k.deviceName
}

func (k *tailscaleKernelHostForwarder) MTU() uint32 {
	return k.mtu
}

func (k *tailscaleKernelHostForwarder) Routes() []netip.Prefix {
	return append([]netip.Prefix{}, k.routes...)
}

func (k *tailscaleKernelHostForwarder) Addresses() []netip.Prefix {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]netip.Prefix{}, k.addresses...)
}

func (k *tailscaleKernelHostForwarder) Configure(v4, v6 netip.Addr) error {
	addresses := tailscaleKernelHostForwardAddressPrefixes(v4, v6)
	if len(addresses) == 0 {
		return errors.New("tailscale kernel host-forward has no Tailscale IPs")
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	if k.configured && tailscaleKernelHostForwardSamePrefixes(k.addresses, addresses) {
		return nil
	}

	link, err := netlink.LinkByName(k.deviceName)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil && !errors.Is(err, unix.EPERM) {
		return err
	}

	for _, address := range addresses {
		added, err := tailscaleKernelHostForwardAddAddress(link, address)
		if err != nil {
			return err
		}
		if added {
			k.ownedAddresses = append(k.ownedAddresses, address)
		}
	}
	for _, route := range k.routes {
		if route.Addr().Is4() && !v4.IsValid() {
			continue
		}
		if route.Addr().Is6() && !v6.IsValid() {
			continue
		}
		added, err := tailscaleKernelHostForwardAddRoute(link, route)
		if err != nil {
			return err
		}
		if added {
			k.ownedRoutes = append(k.ownedRoutes, route)
		}
	}

	k.addresses = addresses
	k.configured = true
	return nil
}

func (k *tailscaleKernelHostForwarder) Close() error {
	if k.tun == nil {
		return nil
	}
	return k.tun.Close()
}

func (k *tailscaleKernelHostForwarder) cleanup() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	link, err := netlink.LinkByName(k.deviceName)
	if err != nil {
		k.ownedAddresses = nil
		k.ownedRoutes = nil
		return nil
	}

	var errs error
	for i := len(k.ownedRoutes) - 1; i >= 0; i-- {
		errs = errors.Join(errs, tailscaleKernelHostForwardDeleteRoute(link, k.ownedRoutes[i]))
	}
	for i := len(k.ownedAddresses) - 1; i >= 0; i-- {
		errs = errors.Join(errs, tailscaleKernelHostForwardDeleteAddress(link, k.ownedAddresses[i]))
	}
	k.ownedAddresses = nil
	k.ownedRoutes = nil
	k.addresses = nil
	k.configured = false
	return errs
}

func tailscaleKernelHostForwardAddressPrefixes(v4, v6 netip.Addr) []netip.Prefix {
	var prefixes []netip.Prefix
	if v4.IsValid() {
		prefixes = append(prefixes, netip.PrefixFrom(v4.Unmap(), 32))
	}
	if v6.IsValid() {
		prefixes = append(prefixes, netip.PrefixFrom(v6.Unmap(), 128))
	}
	return prefixes
}

func tailscaleKernelHostForwardSamePrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func tailscaleKernelHostForwardAddAddress(link netlink.Link, prefix netip.Prefix) (bool, error) {
	addr, err := netlink.ParseAddr(prefix.String())
	if err != nil {
		return false, err
	}
	err = netlink.AddrAdd(link, addr)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.EEXIST) {
		return false, nil
	}
	return false, err
}

func tailscaleKernelHostForwardDeleteAddress(link netlink.Link, prefix netip.Prefix) error {
	addr, err := netlink.ParseAddr(prefix.String())
	if err != nil {
		return err
	}
	err = netlink.AddrDel(link, addr)
	if errors.Is(err, unix.EADDRNOTAVAIL) || errors.Is(err, unix.ENODEV) {
		return nil
	}
	return err
}

func tailscaleKernelHostForwardAddRoute(link netlink.Link, prefix netip.Prefix) (bool, error) {
	route, err := tailscaleKernelHostForwardRoute(link, prefix)
	if err != nil {
		return false, err
	}
	err = netlink.RouteAdd(route)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.EEXIST) {
		return false, nil
	}
	return false, err
}

func tailscaleKernelHostForwardDeleteRoute(link netlink.Link, prefix netip.Prefix) error {
	route, err := tailscaleKernelHostForwardRoute(link, prefix)
	if err != nil {
		return err
	}
	err = netlink.RouteDel(route)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func tailscaleKernelHostForwardRoute(link netlink.Link, prefix netip.Prefix) (*netlink.Route, error) {
	ipNet, err := tailscaleKernelHostForwardIPNet(prefix)
	if err != nil {
		return nil, err
	}
	return &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       ipNet,
	}, nil
}

func tailscaleKernelHostForwardIPNet(prefix netip.Prefix) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(prefix.Masked().String())
	return ipNet, err
}

type tailscaleKernelTUN struct {
	tun       singtun.Tun
	name      string
	mtu       int
	events    chan tstun.Event
	closeHook func() error
	closeOnce sync.Once
	closeErr  error
}

func newTailscaleKernelTUN(name string, mtu uint32, closeHook func() error) (*tailscaleKernelTUN, error) {
	tunIf, err := singtun.New(singtun.Options{
		Name:   name,
		MTU:    mtu,
		Logger: log.SingLogger,
	})
	if err != nil {
		return nil, err
	}
	tun := &tailscaleKernelTUN{
		tun:       tunIf,
		name:      name,
		mtu:       int(mtu),
		events:    make(chan tstun.Event, 1),
		closeHook: closeHook,
	}
	tun.events <- tstun.EventUp
	return tun, nil
}

func (t *tailscaleKernelTUN) File() *os.File {
	return nil
}

func (t *tailscaleKernelTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	if linuxTun, ok := t.tun.(singtun.LinuxTUN); ok {
		return linuxTun.BatchRead(bufs, offset, sizes)
	}
	n, err := t.tun.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (t *tailscaleKernelTUN) Write(bufs [][]byte, offset int) (int, error) {
	if linuxTun, ok := t.tun.(singtun.LinuxTUN); ok {
		if _, err := linuxTun.BatchWrite(bufs, offset); err != nil {
			return 0, err
		}
		return len(bufs), nil
	}
	for i, buf := range bufs {
		if _, err := t.tun.Write(buf[offset:]); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

func (t *tailscaleKernelTUN) MTU() (int, error) {
	return t.mtu, nil
}

func (t *tailscaleKernelTUN) Name() (string, error) {
	return t.name, nil
}

func (t *tailscaleKernelTUN) Events() <-chan tstun.Event {
	return t.events
}

func (t *tailscaleKernelTUN) Close() error {
	t.closeOnce.Do(func() {
		var err error
		if t.closeHook != nil {
			err = errors.Join(err, t.closeHook())
		}
		err = errors.Join(err, t.tun.Close())
		close(t.events)
		t.closeErr = err
	})
	return t.closeErr
}

func (t *tailscaleKernelTUN) BatchSize() int {
	if linuxTun, ok := t.tun.(singtun.LinuxTUN); ok {
		return linuxTun.BatchSize()
	}
	return 1
}
