package geodata_test

import (
	"sync"
	"testing"

	"github.com/metacubex/mihomo/component/geodata"
	RC "github.com/metacubex/mihomo/rules/common"
)

func TestGeoSiteRuleSurvivesTemporarySettings(t *testing.T) {
	geositeFixture(t, 1, 20)
	rule, err := RC.NewGEOSITE("matrix0", "DIRECT")
	if err != nil {
		t.Fatal(err)
	}
	generation := geodata.GeoSiteCacheGeneration()
	loader, matcher := geodata.LoaderName(), geodata.SiteMatcherName()
	// These setters are used by temporary config parsing. A failed parse rolls
	// them back; it must not invalidate already-running rule references.
	geodata.SetLoader("resource-intentionally-missing")
	geodata.SetSiteMatcher("mph")
	if generation != geodata.GeoSiteCacheGeneration() || !rule.MatchDomain("old0.matrix0.invalid") {
		t.Fatal("temporary parse invalidated existing rule")
	}
	geodata.SetLoader(loader)
	geodata.SetSiteMatcher(matcher)
	if generation != geodata.GeoSiteCacheGeneration() || !rule.MatchDomain("old0.matrix0.invalid") {
		t.Fatal("rollback invalidated existing rule")
	}
}
func TestGeoSiteRuleConcurrentReload(t *testing.T) {
	geositeFixture(t, 1, 20)
	rule, err := RC.NewGEOSITE("!matrix0@a", "DIRECT")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if !rule.MatchDomain("unrelated.invalid") {
					t.Error("negation changed")
				}
				if rule.MatchDomain("old0.matrix0.invalid") {
					t.Error("attribute matcher changed")
				}
			}
		}()
	}
	for i := 0; i < 100; i++ {
		geodata.ClearGeoSiteCache()
	}
	wg.Wait()
}
