//go:build linux

package ebpf

import (
	"errors"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestNetNSTopologyIntegration(t *testing.T) {
	if os.Getenv("MIHOMO_EBPF_NETNS_INTEGRATION") != "1" {
		t.Skip("set MIHOMO_EBPF_NETNS_INTEGRATION=1 to create the isolated veth topology")
	}
	require.NoError(t, assertLinkMissing(HostVethName))

	topology, err := CreateNetNSTopology()
	require.NoError(t, err)
	require.NotNil(t, topology)
	t.Cleanup(func() { require.NoError(t, topology.Close()) })

	_, err = netlink.LinkByName(HostVethName)
	require.NoError(t, err)
	require.NoError(t, topology.WithPeerNetNS(func() error {
		for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
			if !hasRoutingRule(t, family) || !hasLocalRoute(t, family) {
				return errors.New("isolated table 100 is incomplete")
			}
		}
		return nil
	}))
	require.NoError(t, topology.Close())
	require.NoError(t, topology.Close())
	require.NoError(t, assertLinkMissing(HostVethName))
}

func TestTCPInboundAttachmentIntegration(t *testing.T) {
	if os.Getenv("MIHOMO_EBPF_TCP_INTEGRATION") != "1" {
		t.Skip("set MIHOMO_EBPF_TCP_INTEGRATION=1 to attach TCP hooks in an isolated topology")
	}
	topology, err := CreateNetNSTopology()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, topology.Close()) })
	datapath, err := LoadDatapath()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, datapath.Close()) })

	tunnel := &tcpInboundTestTunnel{accepted: make(chan *C.Metadata, 1)}
	lan, err := createTestLAN()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, lan.Close()) })
	inboundTCP, err := StartTCPInbound(datapath, topology, lan.hostName, 12345, tunnel)
	require.NoError(t, err)
	require.NotNil(t, inboundTCP.skLookupLink)
	require.NotNil(t, inboundTCP.lanAttachment)
	require.NotNil(t, inboundTCP.peerAttachment)
	require.NoError(t, inboundTCP.Close())
	require.NoError(t, inboundTCP.Close())
}

func TestTCPInboundFlowIntegration(t *testing.T) {
	if os.Getenv("MIHOMO_EBPF_TCP_FLOW_INTEGRATION") != "1" {
		t.Skip("set MIHOMO_EBPF_TCP_FLOW_INTEGRATION=1 to exercise one isolated TCP flow")
	}
	topology, err := CreateNetNSTopology()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, topology.Close()) })
	datapath, err := LoadDatapath()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, datapath.Close()) })
	tunnel := &tcpInboundTestTunnel{accepted: make(chan *C.Metadata, 1)}
	lan, err := createTestLAN()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, lan.Close()) })
	inboundTCP, err := StartTCPInbound(datapath, topology, lan.hostName, 12345, tunnel)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, inboundTCP.Close()) })
	err = lan.withPeer(func() error {
		conn, err := net.DialTimeout("tcp4", "198.51.100.1:443", time.Second)
		if err == nil {
			_ = conn.Close()
		}
		return err
	})
	require.NoError(t, err)
	select {
	case metadata := <-tunnel.accepted:
		require.Equal(t, C.EBPF, metadata.Type)
		require.Equal(t, "198.51.100.1", metadata.DstIP.String())
		require.EqualValues(t, 443, metadata.DstPort)
	case <-time.After(2 * time.Second):
		t.Fatal("transparent TCP listener did not receive the intercepted flow")
	}
}

func TestSKLookupSocketAssignmentIntegration(t *testing.T) {
	if os.Getenv("MIHOMO_EBPF_SK_LOOKUP_INTEGRATION") != "1" {
		t.Skip("set MIHOMO_EBPF_SK_LOOKUP_INTEGRATION=1 to exercise sk_lookup socket assignment")
	}
	topology, err := CreateNetNSTopology()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, topology.Close()) })
	datapath, err := LoadDatapath()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, datapath.Close()) })
	tunnel := &tcpInboundTestTunnel{accepted: make(chan *C.Metadata, 1)}
	inboundTCP, err := StartTCPInbound(datapath, topology, HostVethName, 12345, tunnel)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, inboundTCP.Close()) })

	var probeAddr string
	require.NoError(t, topology.WithPeerNetNS(func() error {
		probe, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return err
		}
		probeAddr = probe.Addr().String()
		return probe.Close()
	}))
	require.NoError(t, topology.WithPeerNetNS(func() error {
		conn, err := net.DialTimeout("tcp4", probeAddr, time.Second)
		if err == nil {
			_ = conn.Close()
		}
		return err
	}))
	select {
	case metadata := <-tunnel.accepted:
		require.Equal(t, C.EBPF, metadata.Type)
	case <-time.After(time.Second):
		t.Fatal("sk_lookup did not select the transparent TCP listener")
	}
}

type tcpInboundTestTunnel struct{ accepted chan *C.Metadata }

func (t *tcpInboundTestTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	t.accepted <- metadata
	_ = conn.Close()
}

func (*tcpInboundTestTunnel) HandleUDPPacket(C.UDPPacket, *C.Metadata) {}

func (*tcpInboundTestTunnel) NatTable() C.NatTable { return nil }

type testLAN struct {
	hostNS   netns.NsHandle
	peerNS   netns.NsHandle
	hostName string
}

func createTestLAN() (lan *testLAN, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hostNS, err := netns.Get()
	if err != nil {
		return nil, err
	}
	created := &testLAN{hostNS: hostNS, peerNS: netns.None(), hostName: "ebpflan0"}
	lan = created
	defer func() {
		_ = netns.Set(hostNS)
		if err != nil {
			_ = created.Close()
		}
	}()
	if err := ensureLinkAbsent(lan.hostName); err != nil {
		return nil, err
	}
	peerNS, err := netns.New()
	if err != nil {
		return nil, err
	}
	lan.peerNS = peerNS
	if err := netns.Set(hostNS); err != nil {
		return nil, err
	}
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: lan.hostName}, PeerName: "ebpflanpeer"}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, err
	}
	host, err := netlink.LinkByName(lan.hostName)
	if err != nil {
		return nil, err
	}
	if err := netlink.AddrAdd(host, &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("192.0.2.1").To4(), Mask: net.CIDRMask(24, 32)}}); err != nil {
		return nil, err
	}
	if err := netlink.LinkSetUp(host); err != nil {
		return nil, err
	}
	peer, err := netlink.LinkByName("ebpflanpeer")
	if err != nil {
		return nil, err
	}
	if err := netlink.LinkSetNsFd(peer, int(peerNS)); err != nil {
		return nil, err
	}
	if err := lan.withPeer(func() error {
		loopback, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(loopback); err != nil {
			return err
		}
		peer, err := netlink.LinkByName("ebpflanpeer")
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(peer, &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("192.0.2.2").To4(), Mask: net.CIDRMask(24, 32)}}); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(peer); err != nil {
			return err
		}
		return netlink.RouteAdd(&netlink.Route{Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, Gw: net.ParseIP("192.0.2.1").To4(), LinkIndex: peer.Attrs().Index})
	}); err != nil {
		return nil, err
	}
	return lan, nil
}

func (lan *testLAN) withPeer(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	originalNS, err := netns.Get()
	if err != nil {
		return err
	}
	defer originalNS.Close()
	if err := netns.Set(lan.peerNS); err != nil {
		return err
	}
	defer netns.Set(originalNS)
	return fn()
}

func (lan *testLAN) Close() error {
	if lan == nil || lan.hostNS == netns.None() {
		return nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	originalNS, err := netns.Get()
	if err != nil {
		return err
	}
	defer originalNS.Close()
	defer netns.Set(originalNS)
	if err := netns.Set(lan.hostNS); err == nil {
		if host, linkErr := netlink.LinkByName(lan.hostName); linkErr == nil {
			_ = netlink.LinkDel(host)
		}
	}
	_ = lan.peerNS.Close()
	_ = lan.hostNS.Close()
	lan.hostNS = netns.None()
	lan.peerNS = netns.None()
	return nil
}

func assertLinkMissing(name string) error {
	_, err := netlink.LinkByName(name)
	if err == nil {
		return errors.New("link still exists")
	}
	var notFound netlink.LinkNotFoundError
	if errors.As(err, &notFound) {
		return nil
	}
	return err
}

func hasRoutingRule(t *testing.T, family int) bool {
	t.Helper()
	rules, err := netlink.RuleList(family)
	require.NoError(t, err)
	for _, rule := range rules {
		if rule.Table == RoutingTable && rule.Priority == routingRule(family).Priority && rule.Mark == TPROXYMark {
			return true
		}
	}
	return false
}

func hasLocalRoute(t *testing.T, family int) bool {
	t.Helper()
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: RoutingTable}, netlink.RT_FILTER_TABLE)
	require.NoError(t, err)
	for _, route := range routes {
		if route.Type == unix.RTN_LOCAL && route.Dst != nil && route.Dst.Mask.String() == "00000000" {
			return true
		}
		if family == unix.AF_INET6 && route.Type == unix.RTN_LOCAL && route.Dst != nil && route.Dst.Mask.String() == "00000000000000000000000000000000" {
			return true
		}
	}
	return false
}
