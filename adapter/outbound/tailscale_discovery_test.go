//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/tailscale/ipn/ipnstate"
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/types/key"
)

func discoveryStatus(peers ...*ipnstate.PeerStatus) *ipnstate.Status {
	s := &ipnstate.Status{
		BackendState: "Running",
		Self:         &ipnstate.PeerStatus{InNetworkMap: true, Online: true},
		Peer:         make(map[key.NodePublic]*ipnstate.PeerStatus),
	}
	for _, peer := range peers {
		s.Peer[key.NewNode().Public()] = peer
	}
	return s
}

func discoveryPeer(id string) *ipnstate.PeerStatus {
	return &ipnstate.PeerStatus{
		ID: tailcfg.StableNodeID(id), HostName: "host-" + id, DNSName: id + ".example.ts.net.",
		TailscaleIPs:   []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a:115c:a1e0::1")},
		ExitNodeOption: true, InNetworkMap: true, Online: true,
	}
}

func TestTailscaleDiscoveryCandidates(t *testing.T) {
	online, offline := discoveryPeer("z-online"), discoveryPeer("a-offline")
	online.ExitNode = true
	offline.Online = false
	ordinary, advertised, stale, expired, noID, noIP := discoveryPeer("ordinary"), discoveryPeer("advertised"), discoveryPeer("stale"), discoveryPeer("expired"), discoveryPeer(""), discoveryPeer("no-ip")
	ordinary.ExitNodeOption = false
	advertised.ExitNodeOption = false
	// Being selected does not confer approved exit-node eligibility.
	advertised.ExitNode = true
	stale.InNetworkMap = false
	expired.Expired = true
	noIP.TailscaleIPs = nil
	s := discoveryStatus(online, offline, ordinary, advertised, stale, expired, noID, noIP, nil)
	s.AuthURL = "secret-auth-url"
	d := tailscaleDiscovery{}
	d.update("Starting", func(context.Context) (*ipnstate.Status, error) { return s, nil })
	result, err := d.query(context.Background(), context.Background())
	if err != nil || result.State != "Ready" || len(result.ExitNodes) != 2 {
		t.Fatalf("query = %+v, %v", result, err)
	}
	if result.ExitNodes[0].ID != "a-offline" || result.ExitNodes[0].Online || result.ExitNodes[1].ID != "z-online" || !result.ExitNodes[1].Online || !result.ExitNodes[1].ExitNode || !result.ExitNodes[1].ExitNodeOption {
		t.Fatalf("unexpected candidates: %+v", result.ExitNodes)
	}
	if result.ExitNodes[1].HostName != online.HostName || result.ExitNodes[1].DNSName != online.DNSName || len(result.ExitNodes[1].TailscaleIPs) != 2 {
		t.Fatalf("missing GUI fields: %+v", result.ExitNodes[1])
	}
	result.ExitNodes[1].TailscaleIPs[0] = netip.Addr{}
	if !online.TailscaleIPs[0].IsValid() {
		t.Fatal("result aliases status addresses")
	}
	data, err := json.Marshal(result)
	if err != nil || strings.Contains(string(data), "secret-auth-url") || strings.Contains(string(data), "PublicKey") {
		t.Fatalf("unexpected serialized result: %s, %v", data, err)
	}
}

func TestTailscaleDiscoveryReadiness(t *testing.T) {
	for _, tc := range []struct {
		name, backend, want string
		self                *ipnstate.PeerStatus
	}{
		{"login", "NeedsLogin", "NeedsLogin", nil},
		{"approval", "NeedsMachineAuth", "NeedsMachineAuth", nil},
		{"starting", "Starting", "Starting", nil},
		{"stopped", "Stopped", "Stopped", nil},
		{"no-self", "Running", "Synchronizing", nil},
		{"no-map", "Running", "Synchronizing", &ipnstate.PeerStatus{Online: true}},
		{"disconnected", "Running", "Disconnected", &ipnstate.PeerStatus{InNetworkMap: true}},
		{"empty", "Running", "Ready", &ipnstate.PeerStatus{InNetworkMap: true, Online: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := tailscaleDiscovery{}
			d.update("Starting", func(context.Context) (*ipnstate.Status, error) {
				return &ipnstate.Status{BackendState: tc.backend, Self: tc.self}, nil
			})
			got, err := d.query(context.Background(), context.Background())
			if err != nil || got.State != tc.want || got.BackendState != tc.backend || got.ExitNodes == nil || len(got.ExitNodes) != 0 {
				t.Fatalf("query = %+v, %v; want %s with empty array", got, err, tc.want)
			}
		})
	}
}

func TestTailscaleDiscoveryIsolation(t *testing.T) {
	var a, b tailscaleDiscovery
	a.update("Starting", func(context.Context) (*ipnstate.Status, error) {
		return discoveryStatus(discoveryPeer("account-a")), nil
	})
	b.update("Starting", func(context.Context) (*ipnstate.Status, error) {
		return discoveryStatus(discoveryPeer("account-b")), nil
	})
	for i, d := range []*tailscaleDiscovery{&a, &b} {
		got, err := d.query(context.Background(), context.Background())
		want := []string{"account-a", "account-b"}[i]
		if err != nil || len(got.ExitNodes) != 1 || got.ExitNodes[0].ID != want {
			t.Fatalf("instance %d: %+v, %v", i, got, err)
		}
	}
}

func TestTailscaleDiscoveryErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status func(context.Context) (*ipnstate.Status, error)
	}{
		{"failure", func(context.Context) (*ipnstate.Status, error) { return nil, errors.New("secret-auth-key") }},
		{"nil-status", func(context.Context) (*ipnstate.Status, error) { return nil, nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := tailscaleDiscovery{}
			d.update("Starting", tc.status)
			if _, err := d.query(context.Background(), context.Background()); err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("error = %v", err)
			}
		})
	}
	d := tailscaleDiscovery{}
	d.update("Error", nil)
	if _, err := d.query(context.Background(), context.Background()); err == nil {
		t.Fatal("initialization failure returned success")
	}
}

func TestTailscaleDiscoveryCancellation(t *testing.T) {
	for _, closeInstance := range []bool{false, true} {
		d := tailscaleDiscovery{}
		entered := make(chan struct{})
		d.update("Starting", func(ctx context.Context) (*ipnstate.Status, error) {
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > tailscaleDiscoveryTimeout {
				t.Error("status call has no bounded timeout")
			}
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		})
		lifetime, closeLifetime := context.WithCancel(context.Background())
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := d.query(ctx, lifetime)
			if closeInstance {
				if err != nil || got.State != "Closed" {
					t.Errorf("closed query = %+v, %v", got, err)
				}
			} else if !errors.Is(err, context.Canceled) {
				t.Errorf("canceled query error = %v", err)
			}
		}()
		<-entered
		if closeInstance {
			closeLifetime()
		} else {
			cancel()
		}
		wg.Wait()
		cancel()
		closeLifetime()
	}
	d := tailscaleDiscovery{}
	d.update("Starting", func(ctx context.Context) (*ipnstate.Status, error) { <-ctx.Done(); return nil, ctx.Err() })
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := d.query(ctx, context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error = %v", err)
	}
}

func TestTailscaleDiscoveryDoesNotStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	instance := &Tailscale{ctx: ctx, cancel: cancel}
	got, err := instance.TailscaleExitNodes(context.Background())
	if err != nil || got.State != "NotStarted" {
		t.Fatalf("unstarted query = %+v, %v", got, err)
	}
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	// Publishing an in-flight start after Close must not resurrect discovery.
	instance.discovery.update("Starting", func(context.Context) (*ipnstate.Status, error) { t.Fatal("closed client was called"); return nil, nil })
	got, err = instance.TailscaleExitNodes(context.Background())
	if err != nil || got.State != "Closed" {
		t.Fatalf("closed query = %+v, %v", got, err)
	}
	if err := instance.start(); err == nil {
		t.Fatal("start after Close succeeded")
	}
}
