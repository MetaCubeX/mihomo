//go:build linux && !android

package neighbor

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func requireIsolatedNetwork(t *testing.T) {
	t.Helper()
	if os.Getenv("MIHOMO_NEIGHBOR_NETNS_TEST") != "1" {
		t.Skip("requires disposable network namespace")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if original := os.Getenv("MIHOMO_NEIGHBOR_ORIGINAL_NETNS"); original == "" || current == original {
		t.Fatal("refusing to change the original network namespace")
	}
}
func runIP(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %v: %v: %s", args, err, out)
	}
	return string(out)
}

// Peer runs in a second namespace, so replies are real ARP/NDP rather than a
// locally assigned address or an injected neighbor-table record.
func TestNeighborPeerProcess(t *testing.T) {
	if os.Getenv("MIHOMO_NEIGHBOR_PEER") != "1" {
		t.Skip("peer helper")
	}
	requireIsolatedNetwork(t)
	fmt.Println("peer-ready")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		t.Fatal("parent did not configure veth")
	}
	runIP(t, "link", "set", "lo", "up")
	runIP(t, "link", "set", "srcmac-peer", "addrgenmode", "none")
	runIP(t, "link", "set", "srcmac-peer", "up")
	runIP(t, "-6", "addr", "add", "fe80::2/64", "dev", "srcmac-peer", "nodad")
	runIP(t, "addr", "add", "192.0.2.2/24", "dev", "srcmac-peer")
	runIP(t, "-6", "addr", "add", "2001:db8::2/64", "dev", "srcmac-peer", "nodad")
	iface, err := net.InterfaceByName("srcmac-peer")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("peer-mac=" + iface.HardwareAddr.String())
	scanner.Scan() // keep the namespace alive until parent closes stdin
}

func TestIsolatedNeighborRecovery(t *testing.T) {
	requireIsolatedNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	peer := exec.CommandContext(ctx, "unshare", "--net", executable, "-test.run=^TestNeighborPeerProcess$")
	peer.Env = append(os.Environ(), "MIHOMO_NEIGHBOR_PEER=1")
	peer.Stderr = os.Stderr
	input, err := peer.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := peer.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = peer.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		input.Close()
		if err := peer.Wait(); err != nil {
			t.Error("peer:", err)
		}
	}()
	scanner := bufio.NewScanner(output)
	if !scanner.Scan() || scanner.Text() != "peer-ready" {
		t.Fatal("peer failed to start", scanner.Text())
	}
	runIP(t, "link", "add", "srcmac-test", "type", "veth", "peer", "name", "srcmac-peer")
	defer exec.Command("ip", "link", "del", "srcmac-test").Run()
	runIP(t, "link", "set", "srcmac-peer", "netns", strconv.Itoa(peer.Process.Pid))
	runIP(t, "link", "set", "srcmac-test", "addrgenmode", "none")
	runIP(t, "link", "set", "srcmac-test", "up")
	runIP(t, "-6", "addr", "add", "fe80::1/64", "dev", "srcmac-test", "nodad")
	runIP(t, "addr", "add", "192.0.2.1/24", "dev", "srcmac-test")
	runIP(t, "-6", "addr", "add", "2001:db8::1/64", "dev", "srcmac-test", "nodad")
	fmt.Fprintln(input, "configure")
	if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), "peer-mac=") {
		t.Fatal("peer failed to configure", scanner.Text())
	}
	addr, err := net.ParseMAC(strings.TrimPrefix(scanner.Text(), "peer-mac="))
	if err != nil {
		t.Fatal(err)
	}
	var want MAC
	copy(want[:], addr)
	r := New(func(err error) { t.Log(err) })
	r.SetEnabled(true)
	defer r.SetEnabled(false)
	v4, v6 := netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::2")
	for _, ip := range []netip.Addr{v4, v6} {
		if _, ok := r.Lookup(0, ip); ok {
			t.Fatal("test must start without target neighbor", ip)
		}
		if _, ok := r.Resolve(ctx, 0, ip); ok {
			t.Fatal("passive lookup discovered absent target", ip)
		}
	}
	if rows := runIP(t, "neigh", "show", "dev", "srcmac-test"); strings.Contains(rows, v4.String()) || strings.Contains(rows, v6.String()) {
		t.Fatal("probe-off mode created a target entry", rows)
	}
	r.Configure(Options{Probe: true, Timeout: time.Second})
	for _, ip := range []netip.Addr{v4, v6} {
		started := time.Now()
		mac, ok := r.Resolve(ctx, 0, ip)
		if !ok || mac != want {
			t.Log(runIP(t, "neigh", "show", "dev", "srcmac-test"))
			t.Fatalf("active discovery %s = %v, %v", ip, mac, ok)
		}
		t.Logf("%s resolved by kernel ARP/NDP in %s", ip, time.Since(started))
	}
	// An absent peer cannot stall a connection past its configured budget.
	r.Configure(Options{Probe: true, Timeout: 80 * time.Millisecond})
	started := time.Now()
	if _, ok := r.Resolve(ctx, 0, netip.MustParseAddr("192.0.2.250")); ok {
		t.Fatal("absent peer matched")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatal("probe timeout exceeded", elapsed)
	}
	// Preserve an administrator's static mapping, including PERMANENT state.
	runIP(t, "neigh", "replace", testIP.String(), "lladdr", testMAC.String(), "nud", "permanent", "dev", "srcmac-test")
	iface, err := net.InterfaceByName("srcmac-test")
	if err != nil {
		t.Fatal(err)
	}
	q, err := openQueryBackend()
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err := q.Probe(ctx, iface.Index, testIP); err != nil {
		t.Fatal(err)
	}
	if rows := runIP(t, "neigh", "show", testIP.String(), "dev", "srcmac-test"); !strings.Contains(rows, "PERMANENT") {
		t.Fatal("probe changed permanent state", rows)
	}
	// A real kernel record absent from a simulated lagging cache is recovered
	// without probing or writing that reply over the subscription's state.
	tab := newTable()
	tab.apply(event{link: true, index: iface.Index, name: "srcmac-test"})
	lagging := recoveryResolver(t, DefaultOptions(), tab, openQueryBackend)
	if mac, ok := lagging.Resolve(ctx, 0, testIP); !ok || mac != testMAC {
		t.Fatal("targeted kernel lookup failed", mac, ok)
	}
	if _, ok := lagging.Lookup(0, testIP); ok {
		t.Fatal("query overwrote event cache")
	}
}
