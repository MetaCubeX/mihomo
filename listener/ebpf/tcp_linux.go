//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/keepalive"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

const (
	tcp4SocketKey uint32 = iota
	tcp6SocketKey
)

// TCPInbound owns the TCP-only eBPF transparent path. Its constructor creates
// listeners in the isolated namespace, publishes their descriptors to the
// sockmap, and attaches only the supplied LAN interface and dae0peer hooks.
type TCPInbound struct {
	datapath       *Datapath
	topology       *NetNSTopology
	listeners      []net.Listener
	skLookupLink   link.Link
	lanAttachment  *tcAttachment
	peerAttachment *tcAttachment
	tunnel         C.Tunnel
	additions      []inbound.Addition
	closeOnce      sync.Once
	closeErr       error
}

// StartTCPInbound activates TCP interception. LANInterface must name a
// dedicated LAN ingress interface; callers must never pass a management
// interface without an explicit deployment decision.
func StartTCPInbound(datapath *Datapath, topology *NetNSTopology, lanInterface string, port uint16, tunnel C.Tunnel, additions ...inbound.Addition) (inboundTCP *TCPInbound, err error) {
	if datapath == nil || datapath.collection == nil {
		return nil, errors.New("eBPF datapath is not loaded")
	}
	if topology == nil {
		return nil, errors.New("eBPF network topology is not available")
	}
	if lanInterface == "" {
		return nil, errors.New("eBPF TCP inbound requires a LAN interface")
	}
	if port == 0 {
		return nil, errors.New("eBPF TCP inbound requires a non-zero transparent port")
	}

	inboundTCP = &TCPInbound{datapath: datapath, topology: topology, tunnel: tunnel, additions: additions}
	defer func() {
		if err != nil {
			_ = inboundTCP.Close()
		}
	}()

	if err := inboundTCP.publishParam(port); err != nil {
		return nil, err
	}
	if err := inboundTCP.openListeners(port); err != nil {
		return nil, err
	}
	lookupProgram := datapath.Program("tproxy_sk_lookup")
	if lookupProgram == nil {
		return nil, errors.New("eBPF datapath has no tproxy_sk_lookup program")
	}
	inboundTCP.skLookupLink, err = link.AttachNetNs(int(topology.peerNS), lookupProgram)
	if err != nil {
		return nil, fmt.Errorf("attach sk_lookup to isolated network namespace: %w", err)
	}

	lanProgram := datapath.Program("tc_lan_ingress")
	peerProgram := datapath.Program("tc_dae0peer_ingress")
	if lanProgram == nil || peerProgram == nil {
		return nil, errors.New("eBPF datapath has incomplete TCP TC programs")
	}
	inboundTCP.lanAttachment, err = attachTCIngress(lanInterface, lanProgram, "mihomo-ebpf-lan")
	if err != nil {
		return nil, err
	}
	err = topology.WithPeerNetNS(func() error {
		inboundTCP.peerAttachment, err = attachTCIngress(PeerVethName, peerProgram, "mihomo-ebpf-peer")
		return err
	})
	if err != nil {
		return nil, err
	}

	for _, listener := range inboundTCP.listeners {
		go inboundTCP.acceptLoop(listener)
	}
	return inboundTCP, nil
}

func (inboundTCP *TCPInbound) publishParam(port uint16) error {
	var ifindex int
	var peerMAC net.HardwareAddr
	err := inboundTCP.topology.WithHostNetNS(func() error {
		link, err := netlink.LinkByName(HostVethName)
		if err != nil {
			return err
		}
		ifindex = link.Attrs().Index
		return nil
	})
	if err != nil {
		return fmt.Errorf("discover dae0 interface index: %w", err)
	}
	if err := inboundTCP.topology.WithPeerNetNS(func() error {
		peer, err := netlink.LinkByName(PeerVethName)
		if err != nil {
			return err
		}
		peerMAC = peer.Attrs().HardwareAddr
		return nil
	}); err != nil {
		return fmt.Errorf("discover dae0peer MAC: %w", err)
	}
	if len(peerMAC) != 6 {
		return fmt.Errorf("dae0peer has invalid MAC length %d", len(peerMAC))
	}
	param := DaeParam{TPROXYPort: uint32(port), DAE0Ifindex: uint32(ifindex), UseRedirectPeer: 1, DAESocketMark: BypassMark}
	copy(param.DAE0PeerMAC[:], peerMAC)
	return inboundTCP.datapath.Map("DAE_PARAM").Update(uint32(0), &param, cebpf.UpdateAny)
}

func (inboundTCP *TCPInbound) openListeners(port uint16) error {
	return inboundTCP.topology.WithPeerNetNS(func() error {
		for _, spec := range []struct {
			network string
			address string
			key     uint32
		}{
			{"tcp4", fmt.Sprintf("0.0.0.0:%d", port), tcp4SocketKey},
			{"tcp6", fmt.Sprintf("[::]:%d", port), tcp6SocketKey},
		} {
			listener, err := transparentListen(spec.network, spec.address)
			if err != nil {
				return fmt.Errorf("listen %s in isolated namespace: %w", spec.network, err)
			}
			if err := publishSocket(inboundTCP.datapath.Map("LISTEN_SOCKET_MAP"), spec.key, listener); err != nil {
				listener.Close()
				return err
			}
			inboundTCP.listeners = append(inboundTCP.listeners, listener)
		}
		return nil
	})
}

func transparentListen(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			if network == "tcp4" {
				socketErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			} else {
				socketErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
				if socketErr == nil {
					socketErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_V6ONLY, 1)
				}
			}
		}); err != nil {
			return err
		}
		return socketErr
	}}
	return lc.Listen(context.Background(), network, address)
}

func publishSocket(socketMap *cebpf.Map, key uint32, listener net.Listener) error {
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		return errors.New("transparent listener is not TCP")
	}
	raw, err := tcpListener.SyscallConn()
	if err != nil {
		return err
	}
	var updateErr error
	if err := raw.Control(func(fd uintptr) {
		updateErr = socketMap.Update(key, uint32(fd), cebpf.UpdateAny)
	}); err != nil {
		return err
	}
	if updateErr != nil {
		return fmt.Errorf("publish listener in LISTEN_SOCKET_MAP[%d]: %w", key, updateErr)
	}
	return nil
}

func (inboundTCP *TCPInbound) acceptLoop(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		if inboundTCP.tunnel == nil {
			_ = conn.Close()
			continue
		}
		go inboundTCP.handle(conn)
	}
}

func (inboundTCP *TCPInbound) handle(conn net.Conn) {
	keepalive.TCPKeepAlive(conn)
	target := socks5.ParseAddrToSocksAddr(conn.LocalAddr())
	inboundTCP.tunnel.HandleTCPConn(inbound.NewSocket(target, conn, C.EBPF, inboundTCP.additions...))
}

func (inboundTCP *TCPInbound) Close() error {
	if inboundTCP == nil {
		return nil
	}
	inboundTCP.closeOnce.Do(func() {
		var errs []error
		if inboundTCP.skLookupLink != nil {
			errs = append(errs, inboundTCP.skLookupLink.Close())
		}
		if inboundTCP.peerAttachment != nil {
			errs = append(errs, inboundTCP.topology.WithPeerNetNS(inboundTCP.peerAttachment.Close))
		}
		if inboundTCP.lanAttachment != nil {
			errs = append(errs, inboundTCP.lanAttachment.Close())
		}
		for key := tcp4SocketKey; key <= tcp6SocketKey; key++ {
			if socketMap := inboundTCP.datapath.Map("LISTEN_SOCKET_MAP"); socketMap != nil {
				errs = append(errs, socketMap.Delete(key))
			}
		}
		for _, listener := range inboundTCP.listeners {
			errs = append(errs, listener.Close())
		}
		inboundTCP.closeErr = errors.Join(errs...)
	})
	return inboundTCP.closeErr
}

type tcAttachment struct {
	filter       *netlink.BpfFilter
	qdisc        netlink.Qdisc
	createdQdisc bool
}

func attachTCIngress(interfaceName string, program *cebpf.Program, name string) (*tcAttachment, error) {
	device, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("find TC interface %s: %w", interfaceName, err)
	}
	qdisc := &netlink.GenericQdisc{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: device.Attrs().Index, Parent: netlink.HANDLE_CLSACT}, QdiscType: "clsact"}
	attachment := &tcAttachment{qdisc: qdisc}
	if err := netlink.QdiscAdd(qdisc); err == nil {
		attachment.createdQdisc = true
	} else if !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("add clsact qdisc on %s: %w", interfaceName, err)
	}
	attachment.filter = &netlink.BpfFilter{
		FilterAttrs:  netlink.FilterAttrs{LinkIndex: device.Attrs().Index, Parent: netlink.HANDLE_MIN_INGRESS, Handle: netlink.MakeHandle(0, 1), Priority: 1, Protocol: unix.ETH_P_ALL},
		Fd:           program.FD(),
		Name:         name,
		DirectAction: true,
	}
	if err := netlink.FilterAdd(attachment.filter); err != nil {
		if attachment.createdQdisc {
			_ = netlink.QdiscDel(qdisc)
		}
		return nil, fmt.Errorf("attach TC ingress program on %s: %w", interfaceName, err)
	}
	return attachment, nil
}

func (attachment *tcAttachment) Close() error {
	if attachment == nil {
		return nil
	}
	var errs []error
	if attachment.filter != nil {
		errs = append(errs, netlink.FilterDel(attachment.filter))
	}
	if attachment.createdQdisc && attachment.qdisc != nil {
		errs = append(errs, netlink.QdiscDel(attachment.qdisc))
	}
	return errors.Join(errs...)
}
