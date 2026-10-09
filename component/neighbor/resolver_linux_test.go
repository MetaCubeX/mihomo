//go:build linux && !android

package neighbor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/jsimonetti/rtnetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

func neighborMessage(t *testing.T, state uint16, addr net.HardwareAddr) syscall.NetlinkMessage {
	t.Helper()
	data, err := (&rtnetlink.NeighMessage{Family: unix.AF_INET, Index: 2, State: state, Attributes: &rtnetlink.NeighAttributes{Address: net.IP(testIP.AsSlice()), LLAddress: addr}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWNEIGH}, Data: data}
}
func TestNeighborEvents(t *testing.T) {
	for _, state := range []uint16{unix.NUD_REACHABLE, unix.NUD_STALE, unix.NUD_DELAY, unix.NUD_PROBE, unix.NUD_PERMANENT, unix.NUD_NOARP, unix.NUD_FAILED, unix.NUD_INCOMPLETE, 0} {
		m := neighborMessage(t, state, testMAC[:])
		e, ok, err := parseEvent(m)
		wantRemoved := state == 0 || state == unix.NUD_FAILED || state == unix.NUD_INCOMPLETE
		if err != nil || !ok || e.remove != wantRemoved || e.ip != testIP {
			t.Fatalf("state %d: %+v, %v, %v", state, e, ok, err)
		}
	}
	for _, mac := range []net.HardwareAddr{nil, {0, 0, 0, 0, 0, 0}, {1, 0, 0, 0, 0, 1}, {2, 0, 0, 0, 0, 0, 0, 1}} {
		e, ok, err := parseEvent(neighborMessage(t, unix.NUD_REACHABLE, mac))
		if err != nil || !ok || !e.remove {
			t.Fatalf("invalid MAC not removed: %v", mac)
		}
	}
	m := neighborMessage(t, unix.NUD_REACHABLE, testMAC[:])
	m.Header.Type = unix.RTM_DELNEIGH
	if e, _, _ := parseEvent(m); !e.remove {
		t.Fatal("deletion ignored")
	}
	m.Header.Type = unix.RTM_NEWNEIGH
	m.Data[0] = unix.AF_BRIDGE
	if _, ok, err := parseEvent(m); ok || err != nil {
		t.Fatal("bridge FDB interpreted as IP neighbor")
	}
	m = neighborMessage(t, unix.NUD_REACHABLE, testMAC[:])
	m.Data[10] = unix.NTF_PROXY
	if e, _, _ := parseEvent(m); !e.remove {
		t.Fatal("proxy neighbor accepted")
	}
	if _, _, err := parseEvent(syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWNEIGH}, Data: []byte{1}}); err == nil {
		t.Fatal("malformed event accepted")
	}
	v6 := netip.MustParseAddr("2001:db8::123")
	data, err := (&rtnetlink.NeighMessage{Family: unix.AF_INET6, Index: 2, State: unix.NUD_STALE, Attributes: &rtnetlink.NeighAttributes{Address: net.IP(v6.AsSlice()), LLAddress: testMAC[:]}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	e, ok, err := parseEvent(syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWNEIGH}, Data: data})
	if err != nil || !ok || e.remove || e.ip != v6 {
		t.Fatal("global IPv6 rejected", e, err)
	}
}

func TestNetlinkErrors(t *testing.T) {
	for _, m := range []syscall.NetlinkMessage{
		{Header: syscall.NlMsghdr{Flags: unix.NLM_F_DUMP_INTR}},
		{Header: syscall.NlMsghdr{Type: unix.NLMSG_OVERRUN}},
		{Header: syscall.NlMsghdr{Type: unix.NLMSG_ERROR}, Data: []byte{0}},
		{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE}, Data: nlenc.Int32Bytes(-int32(unix.ENOBUFS))},
	} {
		if checkMessage(m) == nil {
			t.Fatal("lost/incomplete data accepted", m)
		}
	}
	for _, data := range [][]byte{nil, {0, 0, 0, 0}} {
		if err := checkMessage(syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE}, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
}

type socketReply struct {
	messages []syscall.NetlinkMessage
	flags    int
	pid      uint32
	err      error
}
type scriptedSocket struct {
	t       *testing.T
	replies []socketReply
	sent    int
}

func (s *scriptedSocket) Close() error { return nil }
func (s *scriptedSocket) Sendto(context.Context, []byte, int, unix.Sockaddr) error {
	s.sent++
	return nil
}
func (s *scriptedSocket) Recvmsg(ctx context.Context, p, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
	if len(s.replies) == 0 {
		<-ctx.Done()
		return 0, 0, 0, nil, ctx.Err()
	}
	reply := s.replies[0]
	s.replies = s.replies[1:]
	var wire []byte
	for _, m := range reply.messages {
		msg := netlink.Message{Header: netlink.Header{Length: uint32(16 + len(m.Data)), Type: netlink.HeaderType(m.Header.Type), Flags: netlink.HeaderFlags(m.Header.Flags), Sequence: m.Header.Seq}, Data: m.Data}
		data, err := msg.MarshalBinary()
		if err != nil {
			s.t.Fatal(err)
		}
		wire = append(wire, data...)
	}
	return copy(p, wire), 0, reply.flags, &unix.SockaddrNetlink{Pid: reply.pid}, reply.err
}
func done(seq uint32) syscall.NetlinkMessage {
	return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE, Seq: seq}}
}
func TestSnapshotInterleavedNotification(t *testing.T) {
	linkData, err := (&rtnetlink.LinkMessage{Index: 2, Attributes: &rtnetlink.LinkAttributes{Name: "lan"}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	link := func(seq uint32) syscall.NetlinkMessage {
		return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWLINK, Seq: seq}, Data: linkData}
	}
	old := neighborMessage(t, unix.NUD_REACHABLE, testMAC[:])
	old.Header.Seq = 3
	change := neighborMessage(t, unix.NUD_FAILED, nil)
	fresh := neighborMessage(t, unix.NUD_REACHABLE, []byte{2, 0, 0, 0, 0, 2})
	fresh.Header.Seq = 6
	sock := &scriptedSocket{t: t, replies: []socketReply{
		{messages: []syscall.NetlinkMessage{link(1), done(1)}},
		{messages: []syscall.NetlinkMessage{done(2)}},
		{messages: []syscall.NetlinkMessage{change, old, done(3)}},
		{messages: []syscall.NetlinkMessage{link(4), done(4)}},
		{messages: []syscall.NetlinkMessage{done(5)}},
		{messages: []syscall.NetlinkMessage{fresh, done(6)}},
	}}
	b := &linuxBackend{conn: sock, buffer: make([]byte, 4096)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tab, err := b.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := tab.lookup(0, testIP); !ok || got != (MAC{2, 0, 0, 0, 0, 2}) || sock.sent != 6 {
		t.Fatal("interleaved snapshot not retried", got, ok, sock.sent)
	}
}
func TestReceiveRejectsLossAndNonKernel(t *testing.T) {
	for _, reply := range []socketReply{{flags: unix.MSG_TRUNC}, {pid: 123}, {err: unix.ENOBUFS}} {
		b := &linuxBackend{conn: &scriptedSocket{t: t, replies: []socketReply{reply}}, buffer: make([]byte, 4096)}
		if _, err := b.receive(context.Background()); err == nil {
			t.Fatal("invalid datagram accepted")
		}
	}
}
func TestLiveSnapshotAndCancel(t *testing.T) {
	b, err := openBackend()
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skip("netlink unavailable:", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), snapshotTimeout)
	defer cancel()
	tab, err := b.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tab.links) == 0 {
		t.Fatal("kernel snapshot returned no interfaces")
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := b.Next(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("receive did not cancel", err)
	}
}

// Run only inside a disposable network namespace, for example:
// Set MIHOMO_NEIGHBOR_ORIGINAL_NETNS to the original /proc/self/ns/net link
// before unshare -Urn, and set MIHOMO_NEIGHBOR_NETNS_TEST=1 in the child.
func TestIsolatedNetlinkEvents(t *testing.T) {
	if os.Getenv("MIHOMO_NEIGHBOR_NETNS_TEST") != "1" {
		t.Skip("requires isolated network namespace")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	original := os.Getenv("MIHOMO_NEIGHBOR_ORIGINAL_NETNS")
	if original == "" || self == original {
		t.Fatal("refusing to modify the initial network namespace")
	}
	ip := func(args ...string) {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}
	ip("link", "add", "srcmac0", "type", "veth", "peer", "name", "srcmac1")
	defer exec.Command("ip", "link", "del", "srcmac0").Run()
	ip("link", "set", "srcmac0", "up")
	ip("link", "set", "srcmac1", "up")
	ip("addr", "add", "192.0.2.1/24", "dev", "srcmac0")
	ip("-6", "addr", "add", "2001:db8::1/64", "dev", "srcmac0", "nodad")
	ip("neigh", "replace", "192.0.2.10", "lladdr", testMAC.String(), "nud", "permanent", "dev", "srcmac0")
	r := New(func(err error) { t.Log(err) })
	r.SetEnabled(true)
	defer r.SetEnabled(false)
	if got, ok := r.Lookup(0, testIP); !ok || got != testMAC {
		t.Fatal("initial IPv4 neighbor missing", got, ok)
	}
	v6 := netip.MustParseAddr("2001:db8::10")
	ip("-6", "neigh", "replace", v6.String(), "lladdr", testMAC.String(), "nud", "permanent", "dev", "srcmac0")
	eventually(t, func() bool { mac, ok := r.Lookup(0, v6); return ok && mac == testMAC })
	replacement := MAC{2, 0, 0, 0, 0, 2}
	ip("neigh", "replace", testIP.String(), "lladdr", replacement.String(), "nud", "permanent", "dev", "srcmac0")
	eventually(t, func() bool { mac, ok := r.Lookup(0, testIP); return ok && mac == replacement })
	ip("neigh", "del", testIP.String(), "dev", "srcmac0")
	eventually(t, func() bool { _, ok := r.Lookup(0, testIP); return !ok })
	ip("link", "del", "srcmac0")
	eventually(t, func() bool { _, ok := r.Lookup(0, v6); return !ok })
}
