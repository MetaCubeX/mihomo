package tunnel

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/nat"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

type udpWorkerTestPacket struct {
	C.PacketAdapter
	source string
}

func (p udpWorkerTestPacket) Key() string { return p.source }

type udpWorkerTestTable struct {
	*nat.Table
	deleted chan struct{}
}

func (t udpWorkerTestTable) DeleteSession(key C.UDPSessionKey, sender C.PacketSender) bool {
	deleted := t.Table.DeleteSession(key, sender)
	t.deleted <- struct{}{}
	return deleted
}

func TestProcessUDPDuringSourceClose(t *testing.T) {
	installUDPDestinationTestState(t, nil)
	previousTable, previousStatus := natTable, Status()
	table := udpWorkerTestTable{Table: nat.New(), deleted: make(chan struct{}, 2)}
	natTable = table
	status.Store(Running)
	t.Cleanup(func() {
		natTable = previousTable
		status.Store(previousStatus)
	})
	origin := M.ParseSocksaddr("192.0.2.2:443")
	old := newPacketSender()
	defer old.Close()
	_, source, _ := table.GetOrCreateSession("closing", origin, C.UDPConfig{}, func(C.UDPSessionKey, C.NatSource, C.UDPConfig) C.PacketSender {
		return old
	})
	other := newPacketSender().(*packetSender)
	defer other.Close()
	table.GetOrCreateSession("other", origin, C.UDPConfig{}, func(C.UDPSessionKey, C.NatSource, C.UDPConfig) C.PacketSender {
		return other
	})
	writing, release, written := make(chan struct{}), make(chan struct{}), make(chan struct{})
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer conn.Close()
	go func() {
		defer close(written)
		_, _ = source.WithLocalConn(origin.String(), func() (*net.UDPConn, error) {
			return conn, nil
		}, func(*net.UDPConn) (int, error) {
			close(writing)
			<-release
			return 0, nil
		})
	}()
	<-writing
	go table.DeleteSession(C.NewUDPSessionKey("closing", C.UDPEndpointIndependent, origin), old)
	require.Eventually(t, func() bool {
		_, _, loaded := table.LoadSession("closing", origin)
		return !loaded
	}, time.Second, time.Millisecond)
	queue := make(chan C.PacketAdapter, 2)
	workerDone := make(chan struct{})
	go func() { processUDP(queue); close(workerDone) }()
	defer func() {
		close(release)
		<-written
		<-workerDone
		<-table.deleted
		<-table.deleted
	}()
	for _, source := range []string{"closing", "other"} {
		metadata := &C.Metadata{NetWork: C.UDP, Type: C.INNER, DstIP: origin.Addr, DstPort: origin.Port, SpecialProxy: "missing"}
		queue <- udpWorkerTestPacket{PacketAdapter: C.NewPacketAdapter(&udpTestPacket{}, metadata), source: source}
	}
	close(queue)
	select {
	case packet := <-other.ch:
		packet.Drop()
	case <-time.After(time.Second):
		t.Fatal("one closing source blocked another source on the same processUDP worker")
	}
}

type udpSessionTestConn struct {
	C.PacketConn
	initial  M.Socksaddr
	writes   []M.Socksaddr
	prepares int
}

func (c *udpSessionTestConn) PrepareUDP(_ context.Context, metadata *C.Metadata) (M.Socksaddr, error) {
	c.prepares++
	return metadata.UDP.Target, nil
}

func (c *udpSessionTestConn) InitialDestination() M.Socksaddr { return c.initial }
func (c *udpSessionTestConn) SetReadDeadline(time.Time) error { return nil }
func (c *udpSessionTestConn) UDPCapabilities() C.UDPCapabilities {
	return udpNATTestDomainCapabilities
}

func (c *udpSessionTestConn) WriteTo(data []byte, address net.Addr) (int, error) {
	c.writes = append(c.writes, M.SocksaddrFromNet(address))
	return len(data), nil
}

func TestUDPSessionTargets(t *testing.T) {
	r := installUDPDestinationTestState(t, nil)
	resolver.DefaultHostMapper.(*udpDestinationTestMapper).hosts[netip.MustParseAddr("198.18.0.2")] = "second.example"
	metadata := func(origin string) *C.Metadata {
		address := M.ParseSocksaddr(origin)
		return &C.Metadata{NetWork: C.UDP, DstIP: address.Addr, DstPort: address.Port}
	}
	destination := newUDPDestination(metadata("198.18.0.1:443"), true, "source")
	require.NoError(t, destination.prepare())
	session := newUDPSession(destination)
	t.Cleanup(session.Close)
	wire := &udpSessionTestConn{initial: destination.Target}
	session.bind(wire)
	for _, origin := range []string{"198.18.0.1:443", "198.18.0.2:3478", "198.18.0.1:443", "198.18.0.2:3478"} {
		packet := &udpTestPacket{data: []byte("payload")}
		session.sender.processPacket(wire, C.NewPacketAdapter(packet, metadata(origin)))
		require.EqualValues(t, 1, packet.dropped.Load())
	}
	// One bound connection prepares only the new target, then serves cache hits.
	require.Equal(t, 1, wire.prepares)
	first, second := M.ParseSocksaddr("original.example:443"), M.ParseSocksaddr("second.example:3478")
	require.Equal(t, []M.Socksaddr{first, second, first, second}, wire.writes)
	udpNATRequireReply(t, session.sender.mapping, "second.example:3478", "198.18.0.2:3478")
	require.Empty(t, r.queries)
	queued := &udpTestPacket{}
	session.Send(C.NewPacketAdapter(queued, metadata("198.18.0.1:443")))
	session.Close()
	require.EqualValues(t, 1, queued.dropped.Load())
}
