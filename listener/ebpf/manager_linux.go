//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"net/netip"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/tunnel"
)

// InboundConfig is the lifecycle subset shared by Mihomo and a Premium host
// adapter. This staged manager currently requires one explicit LAN interface;
// the BPF ABI itself remains multi-LAN ready.
type InboundConfig struct {
	Enable                bool
	LANInterfaces         []string
	TProxyPort            uint16
	AutoDirectOffload     bool
	BypassSrcPorts        []uint16
	BypassDstPorts        []uint16
	ProxySrcPorts         []uint16
	ProxyDstPorts         []uint16
	BypassSrcIPs          []netip.Prefix
	BypassDstIPs          []netip.Prefix
	ProxySrcIPs           []netip.Prefix
	ProxyDstIPs           []netip.Prefix
	DirectIPRuleProviders []string
}

// Manager owns the complete eBPF inbound instance and its route-decision
// observer. A failed constructor closes every partially created kernel object.
type Manager struct {
	datapath         *Datapath
	topology         *NetNSTopology
	tcp              *TCPInbound
	udp              *UDPInbound
	restore          func()
	providerCloser   io.Closer
	providerMu       sync.Mutex
	providerPrefixes map[netip.Prefix]struct{}
	providerStop     chan struct{}
	closeOnce        sync.Once
	closeErr         error
}

func StartManager(config InboundConfig, inbound C.Tunnel) (manager *Manager, err error) {
	if !config.Enable {
		return nil, errors.New("eBPF inbound is disabled")
	}
	if len(config.LANInterfaces) != 1 || config.LANInterfaces[0] == "" {
		return nil, errors.New("eBPF inbound currently requires exactly one explicit LAN interface")
	}
	if config.TProxyPort == 0 {
		return nil, errors.New("eBPF inbound requires a non-zero transparent port")
	}
	manager = &Manager{}
	defer func() {
		if err != nil {
			_ = manager.Close()
		}
	}()
	if manager.datapath, err = LoadDatapath(); err != nil {
		return nil, err
	}
	if err = populateStaticPolicy(manager.datapath, config); err != nil {
		return nil, err
	}
	if err = manager.installDirectProviders(config.DirectIPRuleProviders); err != nil {
		return nil, err
	}
	if manager.topology, err = CreateNetNSTopology(); err != nil {
		return nil, err
	}
	lan := config.LANInterfaces[0]
	if manager.tcp, err = StartTCPInbound(manager.datapath, manager.topology, lan, config.TProxyPort, inbound); err != nil {
		return nil, err
	}
	if manager.udp, err = StartUDPInbound(manager.datapath, manager.topology, lan, config.TProxyPort, inbound); err != nil {
		return nil, err
	}
	if err = setDatapathLocalIPv4(manager.datapath, lan); err != nil {
		return nil, err
	}
	if err = setDirectOffloadEnabled(manager.datapath, config.AutoDirectOffload); err != nil {
		return nil, err
	}
	if config.AutoDirectOffload {
		writer, writerErr := NewDatapathDestinationMap(manager.datapath)
		if writerErr != nil {
			return nil, writerErr
		}
		manager.restore = tunnel.SetRoutingDecisionObserver(DecisionObserver(NewOffloader(writer), ConservativeFallbackTTL))
	}
	return manager, nil
}

func setDirectOffloadEnabled(datapath *Datapath, enabled bool) error {
	paramMap := datapath.Map("DAE_PARAM")
	if paramMap == nil {
		return errors.New("eBPF datapath has no DAE_PARAM map")
	}
	param := DaeParam{}
	if err := paramMap.Lookup(uint32(0), &param); err != nil {
		return fmt.Errorf("read eBPF datapath parameters: %w", err)
	}
	if enabled {
		param.DirectOffloadEnabled = 1
	} else {
		param.DirectOffloadEnabled = 0
	}
	if err := paramMap.Update(uint32(0), &param, 0); err != nil {
		return fmt.Errorf("set eBPF direct offload flag: %w", err)
	}
	return nil
}

type ipCIDRDumper interface{ DumpMrs(func(string) bool) }

// installDirectProviders loads only explicitly named ipcidr providers. It is
// intentionally a separate opt-in from generic rule matching: preloading an
// arbitrary domain/classical provider would lose port/sniff precedence.
func (manager *Manager) installDirectProviders(names []string) error {
	if len(names) == 0 {
		return nil
	}
	manager.providerPrefixes = make(map[netip.Prefix]struct{})
	if err := manager.reconcileDirectProviders(names); err != nil {
		return err
	}
	manager.providerCloser = tunnel.Tunnel.RuleUpdateCallback().Register(func(updated P.RuleProvider) {
		for _, name := range names {
			if provider, ok := tunnel.RuleProviders()[name]; ok && provider == updated {
				_ = manager.reconcileDirectProviders(names) // old snapshot stays on failure
				return
			}
		}
	})
	// eBPF is activated by executor before asynchronous HTTP rule providers
	// finish Initial(). Their first update can precede callback registration,
	// so reconcile one delayed snapshot as well. Until then unknown flows stay
	// with Mihomo, which is the safe fallback.
	manager.providerStop = make(chan struct{})
	go func() {
		select {
		case <-time.After(5 * time.Second):
			_ = manager.reconcileDirectProviders(names)
		case <-manager.providerStop:
		}
	}()
	return nil
}

func (manager *Manager) reconcileDirectProviders(names []string) error {
	manager.providerMu.Lock()
	defer manager.providerMu.Unlock()
	next := make(map[netip.Prefix]struct{})
	for _, name := range names {
		provider, ok := tunnel.RuleProviders()[name]
		if !ok {
			return fmt.Errorf("eBPF direct-ip-rule-provider %q does not exist", name)
		}
		if provider.Behavior() != P.IPCIDR {
			return fmt.Errorf("eBPF direct-ip-rule-provider %q is not ipcidr", name)
		}
		dumper, ok := provider.Strategy().(ipCIDRDumper)
		if !ok {
			return fmt.Errorf("eBPF direct-ip-rule-provider %q cannot export prefixes", name)
		}
		dumper.DumpMrs(func(raw string) bool {
			if prefix, err := netip.ParsePrefix(raw); err == nil {
				next[prefix.Masked()] = struct{}{}
			}
			return true
		})
	}
	if err := populatePrefixes(manager.datapath, []struct {
		v4, v6   string
		prefixes []netip.Prefix
	}{{"BYPASS_DST_IPS", "BYPASS_DST_IP6S", prefixSetSlice(next)}}); err != nil {
		return err
	}
	// Delete only prefixes from the prior provider snapshot. Static configured
	// bypass prefixes are never removed by this reconcile.
	for prefix := range manager.providerPrefixes {
		if _, still := next[prefix]; still {
			continue
		}
		if err := deletePrefix(manager.datapath, "BYPASS_DST_IPS", "BYPASS_DST_IP6S", prefix); err != nil {
			return err
		}
	}
	manager.providerPrefixes = next
	return nil
}

func prefixSetSlice(set map[netip.Prefix]struct{}) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(set))
	for prefix := range set {
		result = append(result, prefix)
	}
	return result
}

func deletePrefix(datapath *Datapath, v4Name, v6Name string, prefix netip.Prefix) error {
	prefix = prefix.Masked()
	if prefix.Addr().Is4() {
		return datapath.Map(v4Name).Delete(lpmV4Key{PrefixLen: uint32(prefix.Bits()), Addr: prefix.Addr().As4()})
	}
	return datapath.Map(v6Name).Delete(lpmV6Key{PrefixLen: uint32(prefix.Bits()), Addr: prefix.Addr().As16()})
}

func setDatapathLocalIPv4(datapath *Datapath, lan string) error {
	iface, err := net.InterfaceByName(lan)
	if err != nil {
		return fmt.Errorf("resolve eBPF LAN interface %q: %w", lan, err)
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("read eBPF LAN interface %q addresses: %w", lan, err)
	}
	var address net.IP
	for _, candidate := range addresses {
		if network, ok := candidate.(*net.IPNet); ok && network.IP.To4() != nil {
			address = network.IP.To4()
			break
		}
	}
	if address == nil {
		return fmt.Errorf("eBPF LAN interface %q has no IPv4 address", lan)
	}
	paramMap := datapath.Map("DAE_PARAM")
	if paramMap == nil {
		return errors.New("eBPF datapath has no DAE_PARAM map")
	}
	param := DaeParam{}
	if err := paramMap.Lookup(uint32(0), &param); err != nil {
		return fmt.Errorf("read eBPF datapath parameters: %w", err)
	}
	// The BPF program reads an IPv4 header directly into a host-order u32.
	param.LocalIP = binary.LittleEndian.Uint32(address)
	if err := paramMap.Update(uint32(0), &param, 0); err != nil {
		return fmt.Errorf("set eBPF local IPv4 address: %w", err)
	}
	return nil
}

func populateStaticPolicy(datapath *Datapath, config InboundConfig) error {
	for _, entry := range []struct {
		name  string
		ports []uint16
	}{
		{"BYPASS_SRC_PORTS", config.BypassSrcPorts},
		{"BYPASS_DST_PORTS", config.BypassDstPorts},
		{"PROXY_SRC_PORTS", config.ProxySrcPorts},
		{"PROXY_DST_PORTS", config.ProxyDstPorts},
	} {
		bpfMap := datapath.Map(entry.name)
		if bpfMap == nil {
			return fmt.Errorf("eBPF datapath has no %s map", entry.name)
		}
		for _, port := range entry.ports {
			if port == 0 {
				continue
			}
			// Transport ports in the BPF packet tuple are network-order bytes.
			key := bits.ReverseBytes16(port)
			if err := bpfMap.Update(key, uint8(1), 0); err != nil {
				return fmt.Errorf("populate %s for port %d: %w", entry.name, port, err)
			}
		}
	}
	return populatePrefixes(datapath, []struct {
		v4, v6   string
		prefixes []netip.Prefix
	}{
		{"BYPASS_SRC_IPS", "BYPASS_SRC_IP6S", config.BypassSrcIPs},
		{"BYPASS_DST_IPS", "BYPASS_DST_IP6S", config.BypassDstIPs},
		{"PROXY_SRC_IPS", "PROXY_SRC_IP6S", config.ProxySrcIPs},
		{"PROXY_DST_IPS", "PROXY_DST_IP6S", config.ProxyDstIPs},
	})
}

type lpmV4Key struct {
	PrefixLen uint32
	Addr      [4]byte
}
type lpmV6Key struct {
	PrefixLen uint32
	Addr      [16]byte
}

func populatePrefixes(datapath *Datapath, groups []struct {
	v4, v6   string
	prefixes []netip.Prefix
}) error {
	for _, group := range groups {
		v4, v6 := datapath.Map(group.v4), datapath.Map(group.v6)
		if v4 == nil || v6 == nil {
			return fmt.Errorf("eBPF datapath has no %s/%s maps", group.v4, group.v6)
		}
		for _, prefix := range group.prefixes {
			prefix = prefix.Masked()
			if !prefix.IsValid() {
				return fmt.Errorf("invalid eBPF prefix")
			}
			if prefix.Addr().Is4() {
				if err := v4.Update(lpmV4Key{PrefixLen: uint32(prefix.Bits()), Addr: prefix.Addr().As4()}, uint8(1), 0); err != nil {
					return fmt.Errorf("populate %s %s: %w", group.v4, prefix, err)
				}
			} else if err := v6.Update(lpmV6Key{PrefixLen: uint32(prefix.Bits()), Addr: prefix.Addr().As16()}, uint8(1), 0); err != nil {
				return fmt.Errorf("populate %s %s: %w", group.v6, prefix, err)
			}
		}
	}
	return nil
}

func (manager *Manager) Close() error {
	if manager == nil {
		return nil
	}
	manager.closeOnce.Do(func() {
		var errs []error
		if manager.restore != nil {
			manager.restore()
		}
		if manager.providerCloser != nil {
			errs = append(errs, manager.providerCloser.Close())
		}
		if manager.providerStop != nil {
			close(manager.providerStop)
		}
		if manager.udp != nil {
			errs = append(errs, manager.udp.Close())
		}
		if manager.tcp != nil {
			errs = append(errs, manager.tcp.Close())
		}
		if manager.topology != nil {
			errs = append(errs, manager.topology.Close())
		}
		if manager.datapath != nil {
			errs = append(errs, manager.datapath.Close())
		}
		manager.closeErr = errors.Join(errs...)
	})
	return manager.closeErr
}

func (manager *Manager) String() string {
	if manager == nil {
		return "eBPF inbound disabled"
	}
	return fmt.Sprintf("eBPF inbound on %s", HostVethName)
}
