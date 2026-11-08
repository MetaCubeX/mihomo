package geodata_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/component/geodata"
	_ "github.com/metacubex/mihomo/component/geodata/memconservative"
	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	RC "github.com/metacubex/mihomo/rules/common"
	"google.golang.org/protobuf/proto"
)

type geositeLoader struct {
	geodata.Loader
	calls *atomic.Int64
}

func (l *geositeLoader) LoadSiteByPath(filename, list string) ([]*router.Domain, error) {
	l.calls.Add(1)
	return l.Loader.LoadSiteByPath(filename, list)
}
func geositeWrite(t testing.TB, path, prefix string, categories, records int) {
	t.Helper()
	data := &router.GeoSiteList{Entry: []*router.GeoSite{{CountryCode: "CN", Domain: []*router.Domain{{Type: router.Domain_Domain, Value: "cn.matrix.invalid"}}}}}
	for category := 0; category < categories; category++ {
		entry := &router.GeoSite{CountryCode: fmt.Sprintf("MATRIX%d", category)}
		for i := 0; i < records; i++ {
			attr := "a"
			if i%2 != 0 {
				attr = "b"
			}
			entry.Domain = append(entry.Domain, &router.Domain{Type: router.Domain_Domain, Value: fmt.Sprintf("%s%d.matrix%d.invalid", prefix, i, category), Attribute: []*router.Domain_Attribute{{Key: attr, TypedValue: &router.Domain_Attribute_BoolValue{BoolValue: true}}}})
		}
		data.Entry = append(data.Entry, entry)
	}
	encoded, err := proto.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
}
func geositeFixture(t testing.TB, categories, records int) (string, *atomic.Int64) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, C.GeositeName)
	geositeWrite(t, path, "old", categories, records)
	home, loader, matcher, level := C.Path.HomeDir(), geodata.LoaderName(), geodata.SiteMatcherName(), log.Level()
	calls := new(atomic.Int64)
	geodata.RegisterGeoDataLoaderImplementationCreator("geosite-test-file", func() geodata.LoaderImplementation {
		inner, err := geodata.GetGeoDataLoader("memconservative")
		if err != nil {
			panic(err)
		}
		return &geositeLoader{Loader: inner, calls: calls}
	})
	C.SetHomeDir(dir)
	geodata.SetLoader("geosite-test-file")
	geodata.SetSiteMatcher("succinct")
	log.SetLevel(log.ERROR)
	geodata.ClearGeoSiteCache()
	t.Cleanup(func() {
		geodata.ClearGeoSiteCache()
		C.SetHomeDir(home)
		geodata.SetLoader(loader)
		geodata.SetSiteMatcher(matcher)
		log.SetLevel(level)
	})
	return path, calls
}
func TestGeoSiteReload(t *testing.T) {
	path, _ := geositeFixture(t, 1, 100)
	rule, err := RC.NewGEOSITE("matrix0", "DIRECT")
	if err != nil {
		t.Fatal(err)
	}
	if !rule.MatchDomain("x.old0.matrix0.invalid") {
		t.Fatal("initial rule did not match")
	}
	geositeWrite(t, path, "new", 1, 100)
	geodata.ClearGeoSiteCache()
	if rule.MatchDomain("x.old0.matrix0.invalid") || !rule.MatchDomain("x.new0.matrix0.invalid") {
		t.Fatal("rule retained matcher after data cache reset")
	}
}
func BenchmarkGeoSiteMatch(b *testing.B) {
	geositeFixture(b, 1, 1000)
	for _, key := range []string{"matrix0", "MATRIX0", "matrix0@a"} {
		for _, direct := range []bool{false, true} {
			for _, parallel := range []bool{false, true} {
				b.Run(fmt.Sprintf("%s/direct%v/parallel%v", key, direct, parallel), func(b *testing.B) {
					rule, err := RC.NewGEOSITE(key, "DIRECT")
					if err != nil {
						b.Fatal(err)
					}
					matcher, err := rule.GetDomainMatcher()
					if err != nil {
						b.Fatal(err)
					}
					check := func() bool {
						if direct {
							return matcher.ApplyDomain("x.old0.matrix0.invalid")
						}
						return rule.MatchDomain("x.old0.matrix0.invalid")
					}
					b.ReportAllocs()
					b.ResetTimer()
					if parallel {
						b.RunParallel(func(pb *testing.PB) {
							for pb.Next() {
								if !check() {
									b.Error("lost match")
									return
								}
							}
						})
					} else {
						for i := 0; i < b.N; i++ {
							if !check() {
								b.Fatal("lost match")
							}
						}
					}
				})
			}
		}
	}
}
