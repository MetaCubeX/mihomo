package geodata_test

import (
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	"github.com/metacubex/mihomo/config"
	// Supplies config.temporaryUpdateGeneral through its existing linkname.
	_ "github.com/metacubex/mihomo/hub/executor"
	RC "github.com/metacubex/mihomo/rules/common"
)

type observedGeoSiteLoader struct {
	geodata.Loader
	observe func(string, []*router.Domain)
}

func (l *observedGeoSiteLoader) LoadSiteByPath(path, list string) ([]*router.Domain, error) {
	domains, err := l.Loader.LoadSiteByPath(path, list)
	if err == nil {
		l.observe(list, domains)
	}
	return domains, err
}
func observeGeoSiteLoads(t *testing.T, observe func(string, []*router.Domain)) {
	t.Helper()
	underlying := geodata.LoaderName()
	geodata.RegisterGeoDataLoaderImplementationCreator("geosite-observed", func() geodata.LoaderImplementation {
		loader, err := geodata.GetGeoDataLoader(underlying)
		if err != nil {
			panic(err)
		}
		return &observedGeoSiteLoader{Loader: loader, observe: observe}
	})
	geodata.SetLoader("geosite-observed")
}
func TestGeoSiteLateRuleReference(t *testing.T) {
	path, _ := geositeFixture(t, 1, 20)
	rule, err := RC.NewGEOSITE("matrix0", "DIRECT")
	if err != nil {
		t.Fatal(err)
	}
	started, gate := make(chan struct{}), make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(gate) })
	var calls atomic.Int32
	observeGeoSiteLoads(t, func(list string, _ []*router.Domain) {
		if strings.EqualFold(list, "matrix0") && calls.Add(1) == 1 {
			close(started)
			<-gate
		}
	})
	geodata.ClearGeoSiteCache()
	type result struct {
		matcher router.DomainMatcher
		err     error
	}
	old := make(chan result, 1)
	go func() { m, e := rule.GetDomainMatcher(); old <- result{m, e} }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("old rule load missing")
	}
	geositeWrite(t, path, "new", 1, 20)
	geodata.ClearGeoSiteCache()
	fresh, err := rule.GetDomainMatcher()
	if err != nil || !fresh.ApplyDomain("new0.matrix0.invalid") {
		t.Fatal("new reference missing", err)
	}
	release.Do(func() { close(gate) })
	select {
	case got := <-old:
		if got.err != nil || !got.matcher.ApplyDomain("old0.matrix0.invalid") {
			t.Fatal("old generation mislabeled", got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("late rule load stuck")
	}
	after, err := rule.GetDomainMatcher()
	if err != nil || after.ApplyDomain("old0.matrix0.invalid") || !after.ApplyDomain("new0.matrix0.invalid") || calls.Load() != 2 {
		t.Fatal("late old reference replaced the current generation", err, calls.Load())
	}
}
func TestGeoSiteFailedConfigParseRestoresSettings(t *testing.T) {
	geositeFixture(t, 1, 20)
	rule, err := RC.NewGEOSITE("matrix0", "DIRECT")
	if err != nil {
		t.Fatal(err)
	}
	loader, matcher, generation := geodata.LoaderName(), geodata.SiteMatcherName(), geodata.GeoSiteCacheGeneration()
	raw := config.DefaultRawConfig()
	raw.GeodataLoader = "intentionally-missing-loader"
	raw.GeositeMatcher = "mph"
	raw.Rule = []string{"INTENTIONALLY-INVALID-RULE,example.invalid,DIRECT"}
	if _, err := config.ParseRawConfig(raw); err == nil {
		t.Fatal("invalid rule accepted")
	}
	if geodata.LoaderName() != loader || geodata.SiteMatcherName() != matcher || geodata.GeoSiteCacheGeneration() != generation || !rule.MatchDomain("old0.matrix0.invalid") {
		t.Fatal("failed parse invalidated a running rule or failed to restore settings")
	}
}
func TestGeoSiteRulesDoNotRetainRetiredRawGenerations(t *testing.T) {
	geositeFixture(t, 1, 20)
	built := make(chan chan struct{}, 8)
	observeGeoSiteLoads(t, func(list string, domains []*router.Domain) {
		if strings.EqualFold(list, "matrix0") {
			done := make(chan struct{})
			runtime.SetFinalizer(domains[0], func(*router.Domain) { close(done) })
			built <- done
		}
	})
	geodata.ClearGeoSiteCache()
	active, err := RC.NewGEOSITE("matrix0", "DIRECT")
	if err != nil {
		t.Fatal(err)
	}
	inactive, err := RC.NewGEOSITE("matrix0@a", "DIRECT")
	if err != nil {
		t.Fatal(err)
	}
	retired := []chan struct{}{<-built}
	for i := 0; i < 3; i++ {
		geodata.ClearGeoSiteCache()
		if !active.MatchDomain("old0.matrix0.invalid") {
			t.Fatal("active rule lost match")
		}
		next := <-built
		if i < 2 {
			retired = append(retired, next)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(retired) > 0 && time.Now().Before(deadline) {
		runtime.GC()
		pending := retired[:0]
		for _, done := range retired {
			select {
			case <-done:
			default:
				pending = append(pending, done)
			}
		}
		retired = pending
		time.Sleep(time.Millisecond)
	}
	if len(retired) > 0 {
		t.Fatal("live or inactive rules kept retired raw records", len(retired))
	}
	if !inactive.MatchDomain("old0.matrix0.invalid") || !active.MatchDomain("old0.matrix0.invalid") {
		t.Fatal("retained rules unusable")
	}
	runtime.KeepAlive(active)
	runtime.KeepAlive(inactive)
}
