//go:build !no_easytier

package outbound

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func TestEasyTierLiveJoinAndDial(t *testing.T) {
	network := os.Getenv("EASYTIER_LIVE_NETWORK")
	secret := os.Getenv("EASYTIER_LIVE_SECRET")
	peer := os.Getenv("EASYTIER_LIVE_PEER")
	ipv4 := os.Getenv("EASYTIER_LIVE_IPV4")
	dial := os.Getenv("EASYTIER_LIVE_DIAL")
	if network == "" || secret == "" || peer == "" {
		t.Skip("set EASYTIER_LIVE_NETWORK, EASYTIER_LIVE_SECRET, and EASYTIER_LIVE_PEER to run")
	}

	stateDir := filepath.Join(C.Path.HomeDir(), "easytier-live-test")
	_ = os.RemoveAll(stateDir)
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })

	outbound, err := NewEasyTier(EasyTierOption{
		Name:          "easytier-live",
		NetworkName:   network,
		NetworkSecret: secret,
		IPv4:          ipv4,
		Peers:         []string{peer},
		StateDir:      stateDir,
		UDP:           true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer outbound.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := outbound.ensureStarted(ctx); err != nil {
		t.Fatalf("start EasyTier: %v", err)
	}

	nodes, err := outbound.overlayNodes(ctx)
	if err != nil {
		t.Fatalf("overlay nodes: %v", err)
	}
	if len(nodes) == 0 {
		t.Fatal("no overlay nodes after start")
	}
	t.Logf("overlay nodes=%d instance_id=%s", len(nodes), outbound.instanceID)

	if dial == "" {
		return
	}
	host, portStr, err := net.SplitHostPort(dial)
	if err != nil {
		t.Fatal(err)
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	dstIP, _ := netip.ParseAddr(host)
	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()
	conn, err := outbound.DialContext(dialCtx, &C.Metadata{
		Host:    host,
		DstIP:   dstIP,
		DstPort: uint16(port64),
	})
	if err != nil {
		t.Fatalf("dial %s: %v", dial, err)
	}
	_ = conn.Close()
}
