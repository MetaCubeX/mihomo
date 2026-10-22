package tunnel

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

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
