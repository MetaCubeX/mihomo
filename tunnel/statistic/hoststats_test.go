package statistic

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/gofrs/uuid/v5"
)

func newTrackerInfo(host string, direct bool, up, down int64) *TrackerInfo {
	info := &TrackerInfo{
		UUID:     uuid.Must(uuid.NewV4()),
		Metadata: &C.Metadata{Host: host},
	}
	info.UploadTotal.Store(up)
	info.DownloadTotal.Store(down)
	if direct {
		info.Chain = C.Chain{"DIRECT"}
	} else {
		info.Chain = C.Chain{"Node"}
	}
	return info
}

func newTestStats(t *testing.T) *TrafficStats {
	t.Helper()
	return NewTrafficStats(TrafficStatsOptions{
		Enabled:       true,
		RetentionDays: 30,
		MaxHosts:      100,
	})
}

func TestSampleCountsFullValueOnFirstSight(t *testing.T) {
	s := newTestStats(t)
	now := time.Now()
	info := newTrackerInfo("github.com", false, 100, 2000)

	s.Sample([]*TrackerInfo{info}, now)

	resp := s.Query(now.Unix()-60, now.Unix()+60, "github.com", true, "all", 10)
	if len(resp.Hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(resp.Hosts))
	}
	got := resp.Hosts[0]
	if got.Proxy.Up != 100 || got.Proxy.Down != 2000 {
		t.Fatalf("proxy = %+v, want up=100 down=2000", got.Proxy)
	}
}

func TestSampleCountsDeltaOnly(t *testing.T) {
	s := newTestStats(t)
	now := time.Now()
	info := newTrackerInfo("example.com", false, 100, 200)

	s.Sample([]*TrackerInfo{info}, now)
	info.UploadTotal.Store(300)
	info.DownloadTotal.Store(500)
	s.Sample([]*TrackerInfo{info}, now.Add(time.Second))

	resp := s.Query(now.Unix()-60, now.Unix()+60, "", false, "all", 10)
	if len(resp.Hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(resp.Hosts))
	}
	if resp.Hosts[0].Proxy.Up != 300 || resp.Hosts[0].Proxy.Down != 500 {
		t.Fatalf("got %+v, want up=300 down=500", resp.Hosts[0].Proxy)
	}
}

func TestOnCloseAccountsTail(t *testing.T) {
	s := newTestStats(t)
	now := time.Now()
	info := newTrackerInfo("tail.example", false, 100, 100)

	s.Sample([]*TrackerInfo{info}, now)
	info.UploadTotal.Store(150)
	info.DownloadTotal.Store(400)
	s.OnClose(info)

	resp := s.Query(now.Unix()-60, now.Unix()+60, "tail.example", true, "all", 10)
	if len(resp.Hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(resp.Hosts))
	}
	if resp.Hosts[0].Proxy.Up != 150 || resp.Hosts[0].Proxy.Down != 400 {
		t.Fatalf("got %+v, want up=150 down=400", resp.Hosts[0].Proxy)
	}
	if resp.Hosts[0].Conns != 1 {
		t.Fatalf("conns = %d, want 1", resp.Hosts[0].Conns)
	}
}

func TestDirectAndProxyAreSeparated(t *testing.T) {
	s := newTestStats(t)
	now := time.Now()
	proxy := newTrackerInfo("mixed.example", false, 10, 20)
	direct := newTrackerInfo("mixed.example", true, 1, 2)

	s.Sample([]*TrackerInfo{proxy, direct}, now)

	resp := s.Query(now.Unix()-60, now.Unix()+60, "mixed.example", false, "all", 10)
	got := resp.Hosts[0]
	if got.Proxy.Up != 10 || got.Proxy.Down != 20 {
		t.Fatalf("proxy = %+v", got.Proxy)
	}
	if got.Direct.Up != 1 || got.Direct.Down != 2 {
		t.Fatalf("direct = %+v", got.Direct)
	}

	onlyProxy := s.Query(now.Unix()-60, now.Unix()+60, "mixed.example", false, "proxy", 10)
	if onlyProxy.Hosts[0].Direct.Up != 0 || onlyProxy.Hosts[0].Direct.Down != 0 {
		t.Fatalf("group=proxy should not include direct: %+v", onlyProxy.Hosts[0].Direct)
	}
}

func TestQuerySuffixAndExactMatch(t *testing.T) {
	s := newTestStats(t)
	now := time.Now()
	s.Sample([]*TrackerInfo{
		newTrackerInfo("api.github.com", false, 1, 10),
		newTrackerInfo("github.com", false, 2, 20),
	}, now)

	suffix := s.Query(now.Unix()-60, now.Unix()+60, "github.com", true, "all", 10)
	if len(suffix.Hosts) != 2 {
		t.Fatalf("suffix hosts = %d, want 2", len(suffix.Hosts))
	}
	exact := s.Query(now.Unix()-60, now.Unix()+60, "github.com", false, "all", 10)
	if len(exact.Hosts) != 1 || exact.Hosts[0].Host != "github.com" {
		t.Fatalf("exact hosts = %+v, want only github.com", exact.Hosts)
	}
}

func TestQueryRespectsTimeRange(t *testing.T) {
	s := newTestStats(t)
	now := time.Now()
	s.Sample([]*TrackerInfo{newTrackerInfo("old.example", false, 5, 5)}, now.Add(-2*time.Hour))

	recent := s.Query(now.Unix()-600, now.Unix(), "old.example", true, "all", 10)
	if len(recent.Hosts) != 0 {
		t.Fatalf("recent window should be empty, got %+v", recent.Hosts)
	}
	wide := s.Query(now.Add(-3*time.Hour).Unix(), now.Unix(), "old.example", true, "all", 10)
	if len(wide.Hosts) != 1 {
		t.Fatalf("wide window should include host, got %d", len(wide.Hosts))
	}
}

func TestHostFallsBackToDestinationIP(t *testing.T) {
	s := newTestStats(t)
	now := time.Now()
	info := newTrackerInfo("", false, 1, 1)
	info.Metadata.DstIP = netip.MustParseAddr("203.0.113.9")

	s.Sample([]*TrackerInfo{info}, now)

	resp := s.Query(now.Unix()-60, now.Unix()+60, "203.0.113.9", false, "all", 10)
	if len(resp.Hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(resp.Hosts))
	}
}

func TestEvictionWhenMaxHostsReached(t *testing.T) {
	s := NewTrafficStats(TrafficStatsOptions{Enabled: true, MaxHosts: 2})
	now := time.Now()
	s.Sample([]*TrackerInfo{
		newTrackerInfo("a.example", false, 1, 1),
		newTrackerInfo("b.example", false, 1, 1),
		newTrackerInfo("c.example", false, 1, 1),
	}, now)

	s.mu.Lock()
	count := len(s.hosts)
	s.mu.Unlock()
	if count > 2 {
		t.Fatalf("hosts = %d, want <= 2", count)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-stats.json")
	opts := TrafficStatsOptions{Enabled: true, RetentionDays: 30, MaxHosts: 100, Path: path}
	s := NewTrafficStats(opts)
	now := time.Now()
	s.Sample([]*TrackerInfo{newTrackerInfo("persist.example", false, 7, 11)}, now)
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded := NewTrafficStats(opts)
	resp := loaded.Query(now.Unix()-60, now.Unix()+60, "persist.example", true, "all", 10)
	if len(resp.Hosts) != 1 || resp.Hosts[0].Proxy.Up != 7 || resp.Hosts[0].Proxy.Down != 11 {
		t.Fatalf("loaded = %+v", resp.Hosts)
	}
}

func TestDisabledStatsIsInert(t *testing.T) {
	s := NewTrafficStats(TrafficStatsOptions{Enabled: false})
	now := time.Now()
	s.Sample([]*TrackerInfo{newTrackerInfo("ghost.example", false, 1, 1)}, now)
	if resp := s.Query(now.Unix()-60, now.Unix()+60, "", false, "all", 10); len(resp.Hosts) != 0 {
		t.Fatalf("disabled stats should not record, got %+v", resp.Hosts)
	}
	if s.Enabled() {
		t.Fatal("Enabled() = true, want false")
	}
}
