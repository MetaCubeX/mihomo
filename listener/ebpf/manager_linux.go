//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"math/bits"
	"sync"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

// InboundConfig is the lifecycle subset shared by Mihomo and a Premium host
// adapter. This staged manager currently requires one explicit LAN interface;
// the BPF ABI itself remains multi-LAN ready.
type InboundConfig struct {
	Enable            bool
	LANInterfaces     []string
	TProxyPort        uint16
	AutoDirectOffload bool
	BypassSrcPorts    []uint16
	BypassDstPorts    []uint16
}

// Manager owns the complete eBPF inbound instance and its route-decision
// observer. A failed constructor closes every partially created kernel object.
type Manager struct {
	datapath  *Datapath
	topology  *NetNSTopology
	tcp       *TCPInbound
	udp       *UDPInbound
	restore   func()
	closeOnce sync.Once
	closeErr  error
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
	if err = populateBypassPorts(manager.datapath, config); err != nil {
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
	if config.AutoDirectOffload {
		writer, writerErr := NewDatapathDestinationMap(manager.datapath)
		if writerErr != nil {
			return nil, writerErr
		}
		manager.restore = tunnel.SetRoutingDecisionObserver(DecisionObserver(NewOffloader(writer), ConservativeFallbackTTL))
	}
	return manager, nil
}

func populateBypassPorts(datapath *Datapath, config InboundConfig) error {
	for _, entry := range []struct {
		name  string
		ports []uint16
	}{
		{"BYPASS_SRC_PORTS", config.BypassSrcPorts},
		{"BYPASS_DST_PORTS", config.BypassDstPorts},
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
