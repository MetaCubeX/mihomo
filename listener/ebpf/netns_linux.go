//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	HostVethName = "dae0"
	PeerVethName = "dae0peer"
	RoutingTable = 100
	rulePriority = 10000
)

var (
	hostIPv4 = &net.IPNet{IP: net.ParseIP("169.254.0.1").To4(), Mask: net.CIDRMask(32, 32)}
	peerIPv4 = &net.IPNet{IP: net.ParseIP("169.254.0.2").To4(), Mask: net.CIDRMask(32, 32)}
	hostIPv6 = &net.IPNet{IP: net.ParseIP("fd00::1"), Mask: net.CIDRMask(64, 128)}
	peerIPv6 = &net.IPNet{IP: net.ParseIP("fd00::2"), Mask: net.CIDRMask(64, 128)}
)

type sysctlRestore struct {
	path  string
	value string
}

// NetNSTopology owns the isolated dae0/dae0peer topology. The network
// namespace is intentionally anonymous and held by a file descriptor: no
// global /run/netns entry can be left behind after Close.
type NetNSTopology struct {
	hostNS      netns.NsHandle
	peerNS      netns.NsHandle
	peerSysctls []sysctlRestore
	closeOnce   sync.Once
	closeErr    error
}

// CreateNetNSTopology creates the fixed veth topology required by the
// transparent datapath. It does not attach BPF, alter the default route, or
// configure a physical LAN interface.
func CreateNetNSTopology() (topology *NetNSTopology, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hostNS, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("get host network namespace: %w", err)
	}

	created := &NetNSTopology{hostNS: hostNS, peerNS: netns.None()}
	topology = created
	defer func() {
		if restoreErr := netns.Set(hostNS); err == nil && restoreErr != nil {
			err = fmt.Errorf("restore host network namespace: %w", restoreErr)
		}
		if err != nil {
			_ = created.closeLocked()
		}
	}()

	if err := ensureLinkAbsent(HostVethName); err != nil {
		return nil, err
	}

	peerNS, err := netns.New()
	if err != nil {
		return nil, fmt.Errorf("create isolated network namespace: %w", err)
	}
	topology.peerNS = peerNS
	if err := netns.Set(hostNS); err != nil {
		return nil, fmt.Errorf("return to host network namespace: %w", err)
	}

	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: HostVethName}, PeerName: PeerVethName}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("create %s/%s veth pair: %w", HostVethName, PeerVethName, err)
	}
	hostLink, err := netlink.LinkByName(HostVethName)
	if err != nil {
		return nil, fmt.Errorf("find host veth: %w", err)
	}
	peerLink, err := netlink.LinkByName(PeerVethName)
	if err != nil {
		return nil, fmt.Errorf("find peer veth: %w", err)
	}
	if err := netlink.LinkSetNsFd(peerLink, int(peerNS)); err != nil {
		return nil, fmt.Errorf("move peer veth into isolated network namespace: %w", err)
	}
	if err := configureHostVeth(hostLink); err != nil {
		return nil, err
	}
	if err := topology.configurePeerLocked(); err != nil {
		return nil, err
	}

	return topology, nil
}

func ensureLinkAbsent(name string) error {
	_, err := netlink.LinkByName(name)
	if err == nil {
		return fmt.Errorf("refuse to reuse existing %s; remove the stale topology explicitly", name)
	}
	var notFound netlink.LinkNotFoundError
	if errors.As(err, &notFound) {
		return nil
	}
	return fmt.Errorf("check whether %s exists: %w", name, err)
}

func configureHostVeth(link netlink.Link) error {
	for _, address := range []*net.IPNet{hostIPv4, hostIPv6} {
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: address}); err != nil {
			return fmt.Errorf("add host address %s: %w", address, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring %s up: %w", HostVethName, err)
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		if err := netlink.RuleAdd(routingRule(family)); err != nil {
			return fmt.Errorf("install TPROXY mark rule for family %d: %w", family, err)
		}
		if err := addLocalRoute(family); err != nil {
			return fmt.Errorf("install local route in table %d for family %d: %w", RoutingTable, family, err)
		}
	}
	return nil
}

func routingRule(family int) *netlink.Rule {
	mask := uint32(0xffffffff)
	rule := netlink.NewRule()
	rule.Family = family
	rule.Table = RoutingTable
	rule.Priority = rulePriority
	if family == unix.AF_INET6 {
		// Linux keeps IPv4 and IPv6 policy rules in one priority namespace.
		// Reserve the adjacent value so both mark rules can coexist.
		rule.Priority++
	}
	rule.Mark = TPROXYMark
	rule.Mask = &mask
	return rule
}

func localRoute(family int, loopbackIndex int) *netlink.Route {
	bits := 32
	ip := net.IPv4zero
	if family == unix.AF_INET6 {
		bits = 128
		ip = net.IPv6zero
	}
	return &netlink.Route{
		LinkIndex: loopbackIndex,
		Dst:       &net.IPNet{IP: ip, Mask: net.CIDRMask(0, bits)},
		Family:    family,
		Table:     RoutingTable,
		Type:      unix.RTN_LOCAL,
		Scope:     netlink.SCOPE_HOST,
	}
}

func addLocalRoute(family int) error {
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}
	return netlink.RouteAdd(localRoute(family, loopback.Attrs().Index))
}

func (topology *NetNSTopology) configurePeerLocked() error {
	if err := netns.Set(topology.peerNS); err != nil {
		return fmt.Errorf("enter isolated network namespace: %w", err)
	}
	peer, err := netlink.LinkByName(PeerVethName)
	if err != nil {
		return fmt.Errorf("find peer veth in isolated network namespace: %w", err)
	}
	for _, address := range []*net.IPNet{peerIPv4, peerIPv6} {
		if err := netlink.AddrAdd(peer, &netlink.Addr{IPNet: address}); err != nil {
			return fmt.Errorf("add peer address %s: %w", address, err)
		}
	}
	if err := netlink.LinkSetUp(peer); err != nil {
		return fmt.Errorf("bring %s up: %w", PeerVethName, err)
	}
	return topology.setPeerSysctlsLocked()
}

func (topology *NetNSTopology) setPeerSysctlsLocked() error {
	settings := []struct {
		path  string
		value string
	}{
		{"/proc/sys/net/ipv4/ip_forward", "1"},
		{"/proc/sys/net/ipv4/conf/all/rp_filter", "0"},
		{"/proc/sys/net/ipv6/conf/all/forwarding", "1"},
	}
	for _, setting := range settings {
		previous, err := os.ReadFile(setting.path)
		if err != nil {
			return fmt.Errorf("read isolated namespace sysctl %s: %w", setting.path, err)
		}
		topology.peerSysctls = append(topology.peerSysctls, sysctlRestore{path: setting.path, value: string(previous)})
		if err := os.WriteFile(setting.path, []byte(setting.value+"\n"), 0); err != nil {
			return fmt.Errorf("set isolated namespace sysctl %s: %w", setting.path, err)
		}
	}
	return nil
}

// Close restores isolated-namespace sysctls, removes table-100 rules and
// routes, deletes both veth ends, and closes namespace descriptors. It is
// safe to call repeatedly, including after an interrupted creation.
func (topology *NetNSTopology) Close() error {
	if topology == nil {
		return nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	topology.closeOnce.Do(func() { topology.closeErr = topology.closeLocked() })
	return topology.closeErr
}

func (topology *NetNSTopology) closeLocked() error {
	if topology.hostNS == netns.None() {
		return nil
	}
	originalNS, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get current network namespace for cleanup: %w", err)
	}
	defer originalNS.Close()
	defer netns.Set(originalNS) // best effort: callers must never be left in the peer namespace

	var cleanupErr error
	if err := netns.Set(topology.hostNS); err != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("enter host network namespace for cleanup: %w", err))
	} else {
		for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
			if err := ignoreNotFound(netlink.RuleDel(routingRule(family))); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove table-%d TPROXY rule: %w", RoutingTable, err))
			}
			loopback, err := netlink.LinkByName("lo")
			if err == nil {
				if err := ignoreNotFound(netlink.RouteDel(localRoute(family, loopback.Attrs().Index))); err != nil {
					cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove table-%d local route: %w", RoutingTable, err))
				}
			}
		}
	}

	if topology.peerNS != netns.None() && netns.Set(topology.peerNS) == nil {
		for index := len(topology.peerSysctls) - 1; index >= 0; index-- {
			restore := topology.peerSysctls[index]
			if err := os.WriteFile(restore.path, []byte(restore.value), 0); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("restore isolated namespace sysctl %s: %w", restore.path, err))
			}
		}
		if peer, err := netlink.LinkByName(PeerVethName); err == nil {
			if err := ignoreNotFound(netlink.LinkDel(peer)); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("delete %s: %w", PeerVethName, err))
			}
		}
	}
	if netns.Set(topology.hostNS) == nil {
		if host, err := netlink.LinkByName(HostVethName); err == nil {
			if err := ignoreNotFound(netlink.LinkDel(host)); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("delete %s: %w", HostVethName, err))
			}
		}
	}
	if topology.peerNS != netns.None() {
		cleanupErr = errors.Join(cleanupErr, topology.peerNS.Close())
		topology.peerNS = netns.None()
	}
	cleanupErr = errors.Join(cleanupErr, topology.hostNS.Close())
	topology.hostNS = netns.None()
	return cleanupErr
}

func ignoreNotFound(err error) error {
	if err == nil || errors.Is(err, unix.ESRCH) || errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "cannot find") {
		return nil
	}
	return err
}
