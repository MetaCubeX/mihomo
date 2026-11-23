package tunnel

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

var testFakeIPRange = netip.MustParsePrefix("198.18.0.0/16")

// testHostMapper implements only what the UDP write-back path asks of a mapper.
type testHostMapper struct{ enabled bool }

func (m testHostMapper) FakeIPEnabled() bool  { return m.enabled }
func (m testHostMapper) MappingEnabled() bool { return false }
func (m testHostMapper) IsFakeIP(addr netip.Addr) bool {
	return m.enabled && testFakeIPRange.Contains(addr)
}
func (m testHostMapper) IsFakeBroadcastIP(netip.Addr) bool      { return false }
func (m testHostMapper) IsExistFakeIP(netip.Addr) bool          { return false }
func (m testHostMapper) FindHostByIP(netip.Addr) (string, bool) { return "", false }
func (m testHostMapper) FlushFakeIP() error                     { return nil }
func (m testHostMapper) InsertHostByIP(netip.Addr, string)      {}
func (m testHostMapper) StoreFakePoolState()                    {}

type countingWriteBack struct{ calls int }

func (w *countingWriteBack) WriteBack(b []byte, _ net.Addr) (int, error) {
	w.calls++
	return len(b), nil
}

// stubPacketConn serves one reply and then fails the read so the loop exits.
type stubPacketConn struct {
	N.EnhancePacketConn
	C.Connection
	reply  net.Addr
	served bool
}

func (c *stubPacketConn) SetReadDeadline(time.Time) error               { return nil }
func (c *stubPacketConn) Close() error                                  { return nil }
func (c *stubPacketConn) ResolveUDP(context.Context, *C.Metadata) error { return nil }

func (c *stubPacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	if c.served {
		return nil, nil, nil, net.ErrClosed
	}
	c.served = true
	return []byte("stun-reply"), nil, c.reply, nil
}

type stubSender struct{ C.PacketSender }

func (stubSender) Close()                                     {}
func (stubSender) RestoreReadFrom(addr netip.Addr) netip.Addr { return addr }

func TestHandleUDPToLocalWriteBack(t *testing.T) {
	previous := resolver.DefaultHostMapper
	t.Cleanup(func() { resolver.DefaultHostMapper = previous })

	tests := []struct {
		name          string
		fakeIPEnabled bool
		replyIP       string
		wantBack      int
	}{
		{"fake-ip source is our own write-back", true, "198.18.5.55", 0},
		{"real source is forwarded", true, "1.1.1.1", 1},
		{"redir-host is unaffected", false, "198.18.5.55", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver.DefaultHostMapper = testHostMapper{enabled: tt.fakeIPEnabled}
			wb := &countingWriteBack{}
			pc := &stubPacketConn{reply: &net.UDPAddr{IP: net.ParseIP(tt.replyIP), Port: 3478}}
			handleUDPToLocal(wb, pc, stubSender{}, tt.name, netip.MustParseAddrPort("1.1.1.1:3478"))
			if wb.calls != tt.wantBack {
				t.Fatalf("write-back calls = %d, want %d", wb.calls, tt.wantBack)
			}
		})
	}
}
