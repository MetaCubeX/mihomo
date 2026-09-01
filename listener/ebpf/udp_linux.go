//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/pool"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/tproxy"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
)

const (
	udp4SocketKey uint32 = 2
	udp6SocketKey uint32 = 3
)

// UDPInbound owns UDP interception and its L2 return path. Packets are
// delivered to transparent sockets in the isolated namespace; replies match
// REDIRECT_TRACK and are sent directly back to the original LAN interface.
type UDPInbound struct {
	datapath        *Datapath
	topology        *NetNSTopology
	listeners       []*net.UDPConn
	skLookupLink    link.Link
	lanAttachment   *tcAttachment
	peerAttachment  *tcAttachment
	replyAttachment *tcAttachment
	tunnel          C.Tunnel
	additions       []inbound.Addition
	closeOnce       sync.Once
	closeErr        error
}

// StartUDPInbound activates UDP interception on one explicit LAN ingress
// interface. It is intentionally separate from TCP during the staged rollout;
// the transactional manager combines both lifecycles in a later task.
func StartUDPInbound(datapath *Datapath, topology *NetNSTopology, lanInterface string, port uint16, tunnel C.Tunnel, additions ...inbound.Addition) (inboundUDP *UDPInbound, err error) {
	if datapath == nil || datapath.collection == nil {
		return nil, errors.New("eBPF datapath is not loaded")
	}
	if topology == nil {
		return nil, errors.New("eBPF network topology is not available")
	}
	if lanInterface == "" {
		return nil, errors.New("eBPF UDP inbound requires a LAN interface")
	}
	if port == 0 {
		return nil, errors.New("eBPF UDP inbound requires a non-zero transparent port")
	}

	inboundUDP = &UDPInbound{datapath: datapath, topology: topology, tunnel: tunnel, additions: additions}
	defer func() {
		if err != nil {
			_ = inboundUDP.Close()
		}
	}()
	if err := inboundUDP.publishParam(port); err != nil {
		return nil, err
	}
	if err := inboundUDP.openListeners(port); err != nil {
		return nil, err
	}
	lookupProgram := datapath.Program("tproxy_sk_lookup")
	if lookupProgram == nil {
		return nil, errors.New("eBPF datapath has no tproxy_sk_lookup program")
	}
	inboundUDP.skLookupLink, err = link.AttachNetNs(int(topology.peerNS), lookupProgram)
	if err != nil {
		return nil, fmt.Errorf("attach UDP sk_lookup to isolated network namespace: %w", err)
	}
	lanProgram, peerProgram, replyProgram := datapath.Program("tc_lan_ingress"), datapath.Program("tc_dae0peer_ingress"), datapath.Program("tc_dae0_ingress")
	if lanProgram == nil || peerProgram == nil || replyProgram == nil {
		return nil, errors.New("eBPF datapath has incomplete UDP TC programs")
	}
	inboundUDP.lanAttachment, err = attachTCIngress(lanInterface, lanProgram, "mihomo-ebpf-udp-lan")
	if err != nil {
		return nil, err
	}
	inboundUDP.replyAttachment, err = attachTCIngress(HostVethName, replyProgram, "mihomo-ebpf-udp-reply")
	if err != nil {
		return nil, err
	}
	err = topology.WithPeerNetNS(func() error {
		inboundUDP.peerAttachment, err = attachTCIngress(PeerVethName, peerProgram, "mihomo-ebpf-udp-peer")
		return err
	})
	if err != nil {
		return nil, err
	}
	for _, listener := range inboundUDP.listeners {
		go inboundUDP.serve(listener)
	}
	return inboundUDP, nil
}

func (inboundUDP *UDPInbound) publishParam(port uint16) error {
	var ifindex int
	var peerMAC net.HardwareAddr
	if err := inboundUDP.topology.WithHostNetNS(func() error {
		device, err := netlink.LinkByName(HostVethName)
		if err == nil {
			ifindex = device.Attrs().Index
		}
		return err
	}); err != nil {
		return fmt.Errorf("discover dae0 interface index: %w", err)
	}
	if err := inboundUDP.topology.WithPeerNetNS(func() error {
		peer, err := netlink.LinkByName(PeerVethName)
		if err == nil {
			peerMAC = peer.Attrs().HardwareAddr
		}
		return err
	}); err != nil {
		return fmt.Errorf("discover dae0peer MAC: %w", err)
	}
	if len(peerMAC) != 6 {
		return fmt.Errorf("dae0peer has invalid MAC length %d", len(peerMAC))
	}
	param := DaeParam{TPROXYPort: uint32(port), DAE0Ifindex: uint32(ifindex), UseRedirectPeer: 1, DAESocketMark: BypassMark}
	copy(param.DAE0PeerMAC[:], peerMAC)
	return inboundUDP.datapath.Map("DAE_PARAM").Update(uint32(0), &param, cebpf.UpdateAny)
}

func (inboundUDP *UDPInbound) openListeners(port uint16) error {
	return inboundUDP.topology.WithPeerNetNS(func() error {
		for _, spec := range []struct {
			network, address string
			key              uint32
		}{
			{"udp4", fmt.Sprintf("0.0.0.0:%d", port), udp4SocketKey},
			{"udp6", fmt.Sprintf("[::]:%d", port), udp6SocketKey},
		} {
			listener, err := transparentListenUDP(spec.network, spec.address)
			if err != nil {
				return fmt.Errorf("listen %s in isolated namespace: %w", spec.network, err)
			}
			if err := publishUDPSocket(inboundUDP.datapath.Map("LISTEN_SOCKET_MAP"), spec.key, listener); err != nil {
				_ = listener.Close()
				return err
			}
			inboundUDP.listeners = append(inboundUDP.listeners, listener)
		}
		return nil
	})
}

func transparentListenUDP(network, address string) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			if socketErr == nil {
				socketErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			}
			if socketErr == nil {
				socketErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
			}
			if socketErr == nil {
				socketErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVTOS, 1)
			}
			if network == "udp6" && socketErr == nil {
				socketErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, 0x4b, 1) // IPV6_TRANSPARENT
			}
			if network == "udp6" && socketErr == nil {
				socketErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, 0x4a, 1) // IPV6_RECVORIGDSTADDR
			}
			if network == "udp6" && socketErr == nil {
				socketErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVTCLASS, 1)
			}
			if network == "udp6" && socketErr == nil {
				socketErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_V6ONLY, 1)
			}
		}); err != nil {
			return err
		}
		return socketErr
	}}
	packetConn, err := lc.ListenPacket(context.Background(), network, address)
	if err != nil {
		return nil, err
	}
	listener, ok := packetConn.(*net.UDPConn)
	if !ok {
		_ = packetConn.Close()
		return nil, errors.New("transparent listener is not UDP")
	}
	return listener, nil
}

func publishUDPSocket(socketMap *cebpf.Map, key uint32, listener *net.UDPConn) error {
	raw, err := listener.SyscallConn()
	if err != nil {
		return err
	}
	var updateErr error
	if err := raw.Control(func(fd uintptr) { updateErr = socketMap.Update(key, uint32(fd), cebpf.UpdateAny) }); err != nil {
		return err
	}
	if updateErr != nil {
		return fmt.Errorf("publish UDP listener in LISTEN_SOCKET_MAP[%d]: %w", key, updateErr)
	}
	return nil
}

func (inboundUDP *UDPInbound) serve(listener *net.UDPConn) {
	oob := make([]byte, 1024)
	for {
		buf := pool.Get(pool.UDPBufferSize)
		n, oobn, _, source, err := listener.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			pool.Put(buf)
			return
		}
		destination, err := tproxy.OriginalDestination(oob[:oobn])
		if err != nil {
			pool.Put(buf)
			continue
		}
		dscp, _ := tproxy.DSCP(oob[:oobn])
		if source.Addr().Is4() {
			source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
		}
		if inboundUDP.tunnel == nil {
			pool.Put(buf)
			continue
		}
		additions := append(slices.Clip(inboundUDP.additions), inbound.WithDSCP(dscp))
		packet := &udpPacket{listener: listener, topology: inboundUDP.topology, buffer: buf[:n], client: source}
		tproxy.DispatchUDPPacket(packet, destination, inboundUDP.tunnel, C.EBPF, additions...)
	}
}

type udpPacket struct {
	listener *net.UDPConn
	topology *NetNSTopology
	buffer   []byte
	client   netip.AddrPort
}

func (packet *udpPacket) Data() []byte { return packet.buffer }

func (packet *udpPacket) WriteBack(data []byte, source net.Addr) (int, error) {
	udpSource, ok := source.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("transparent UDP reply source must be *net.UDPAddr, got %T", source)
	}
	return packet.writeReply(data, udpSource.AddrPort())
}

func (packet *udpPacket) writeReply(data []byte, source netip.AddrPort) (int, error) {
	var written int
	err := packet.topology.WithPeerNetNS(func() error {
		conn, err := transparentDialUDP(source, packet.client)
		if err != nil {
			return err
		}
		defer conn.Close()
		written, err = conn.Write(data)
		return err
	})
	return written, err
}

func transparentDialUDP(source, destination netip.AddrPort) (*net.UDPConn, error) {
	network := "udp6"
	if source.Addr().Is4() && destination.Addr().Is4() {
		network = "udp4"
	}
	return transparentBoundUDP(network, source, destination)
}

func transparentBoundUDP(network string, source, destination netip.AddrPort) (*net.UDPConn, error) {
	family := unix.AF_INET6
	if network == "udp4" {
		family = unix.AF_INET
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*net.UDPConn, error) { _ = unix.Close(fd); return nil, cause }
	err = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	if err == nil && family == unix.AF_INET6 {
		err = unix.SetsockoptInt(fd, unix.SOL_IPV6, 0x4b, 1)
	}
	if err != nil {
		return fail(err)
	}
	var local, remote unix.Sockaddr
	if family == unix.AF_INET {
		local = &unix.SockaddrInet4{Addr: source.Addr().As4(), Port: int(source.Port())}
		remote = &unix.SockaddrInet4{Addr: destination.Addr().As4(), Port: int(destination.Port())}
	} else {
		local = &unix.SockaddrInet6{Addr: source.Addr().As16(), Port: int(source.Port())}
		remote = &unix.SockaddrInet6{Addr: destination.Addr().As16(), Port: int(destination.Port())}
	}
	if err := unix.Bind(fd, local); err != nil {
		return fail(err)
	}
	if err := unix.Connect(fd, remote); err != nil {
		return fail(err)
	}
	file := os.NewFile(uintptr(fd), "mihomo-ebpf-udp-reply")
	defer file.Close()
	conn, err := net.FileConn(file)
	if err != nil {
		return nil, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("transparent bound UDP socket is not UDP")
	}
	return udpConn, nil
}

func (packet *udpPacket) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(packet.client) }
func (packet *udpPacket) InAddr() net.Addr    { return packet.listener.LocalAddr() }
func (packet *udpPacket) Drop() {
	if packet.buffer != nil {
		pool.Put(packet.buffer)
		packet.buffer = nil
	}
}

func (inboundUDP *UDPInbound) Close() error {
	if inboundUDP == nil {
		return nil
	}
	inboundUDP.closeOnce.Do(func() {
		var errs []error
		if inboundUDP.skLookupLink != nil {
			errs = append(errs, inboundUDP.skLookupLink.Close())
		}
		if inboundUDP.peerAttachment != nil {
			errs = append(errs, inboundUDP.topology.WithPeerNetNS(inboundUDP.peerAttachment.Close))
		}
		if inboundUDP.replyAttachment != nil {
			errs = append(errs, inboundUDP.replyAttachment.Close())
		}
		if inboundUDP.lanAttachment != nil {
			errs = append(errs, inboundUDP.lanAttachment.Close())
		}
		for key := udp4SocketKey; key <= udp6SocketKey; key++ {
			if socketMap := inboundUDP.datapath.Map("LISTEN_SOCKET_MAP"); socketMap != nil {
				errs = append(errs, socketMap.Delete(key))
			}
		}
		for _, listener := range inboundUDP.listeners {
			errs = append(errs, listener.Close())
		}
		inboundUDP.closeErr = errors.Join(errs...)
	})
	return inboundUDP.closeErr
}
