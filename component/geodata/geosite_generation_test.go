package geodata

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/geodata/router"
)

type generationTestLoader struct {
	LoaderImplementation
	load func(string) ([]*router.Domain, error)
}

func (l *generationTestLoader) LoadSiteByPath(_ string, list string) ([]*router.Domain, error) {
	return l.load(list)
}
func generationTestFixture(t *testing.T, load func(string) ([]*router.Domain, error)) {
	t.Helper()
	oldLoader, oldMatcher := LoaderName(), SiteMatcherName()
	RegisterGeoDataLoaderImplementationCreator("resource-generation", func() LoaderImplementation { return &generationTestLoader{load: load} })
	SetLoader("resource-generation")
	SetSiteMatcher("succinct")
	ClearGeoSiteCache()
	t.Cleanup(func() { SetLoader(oldLoader); SetSiteMatcher(oldMatcher); ClearGeoSiteCache() })
}
func generationDomains(name string) []*router.Domain {
	return []*router.Domain{{Type: router.Domain_Domain, Value: name}}
}
func TestGeoSiteOldBuildCannotPoisonNewGeneration(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var calls atomic.Int64
	generationTestFixture(t, func(string) ([]*router.Domain, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
			return generationDomains("old.invalid"), nil
		}
		return generationDomains("new.invalid"), nil
	})
	type result struct {
		matcher    router.DomainMatcher
		generation uint64
		err        error
	}
	old := make(chan result, 1)
	oldGeneration := GeoSiteCacheGeneration()
	go func() { m, g, e := LoadGeoSiteMatcherWithGeneration("test"); old <- result{m, g, e} }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("old build not started")
	}
	ClearGeoSiteCache()
	newGeneration := GeoSiteCacheGeneration()
	fresh, generation, err := LoadGeoSiteMatcherWithGeneration("test")
	if err != nil || generation != newGeneration || generation == oldGeneration || !fresh.ApplyDomain("new.invalid") {
		t.Fatal("new generation did not build independently", generation, err)
	}
	once.Do(func() { close(release) })
	select {
	case got := <-old:
		if got.err != nil || got.generation != oldGeneration || !got.matcher.ApplyDomain("old.invalid") {
			t.Fatal("old build mislabeled", got.generation, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("old build stuck")
	}
	again, generation, err := LoadGeoSiteMatcherWithGeneration("test")
	if err != nil || generation != newGeneration || again.ApplyDomain("old.invalid") || !again.ApplyDomain("new.invalid") {
		t.Fatal("late old build poisoned current cache", err)
	}
}
func TestGeoSiteSharedFailureCanRetry(t *testing.T) {
	gate := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(gate) })
	var fail atomic.Bool
	fail.Store(true)
	generationTestFixture(t, func(string) ([]*router.Domain, error) {
		if fail.Load() {
			<-gate
			return nil, errors.New("synthetic decode failure")
		}
		return generationDomains("success.invalid"), nil
	})
	var wg, ready sync.WaitGroup
	ready.Add(32)
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready.Done()
			<-start
			if _, err := LoadGeoSiteMatcher("retry"); err == nil {
				t.Error("failure lost")
			}
		}()
	}
	ready.Wait()
	close(start)
	// A held loader allows concurrent requests to join; late failures must also
	// remain retryable. No cached error may survive the completed burst.
	time.Sleep(10 * time.Millisecond)
	release.Do(func() { close(gate) })
	wg.Wait()
	fail.Store(false)
	matcher, err := LoadGeoSiteMatcher("retry")
	if err != nil || !matcher.ApplyDomain("success.invalid") {
		t.Fatal("failure stuck in success cache", err)
	}
}
func TestGeoSiteGenerationConcurrentClear(t *testing.T) {
	generationTestFixture(t, func(string) ([]*router.Domain, error) { return generationDomains("stable.invalid"), nil })
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				matcher, _, err := LoadGeoSiteMatcherWithGeneration("test")
				if err != nil || !matcher.ApplyDomain("stable.invalid") {
					t.Error("concurrent load failed", err)
				}
			}
		}()
	}
	for i := 0; i < 100; i++ {
		ClearGeoSiteCache()
	}
	wg.Wait()
}
func TestGeoSiteRetiredStateNotHeldByMatcher(t *testing.T) {
	generationTestFixture(t, func(string) ([]*router.Domain, error) { return generationDomains("retained.invalid"), nil })
	retired := make(chan struct{})
	matcher := func() router.DomainMatcher {
		matcher, err := LoadGeoSiteMatcher("test")
		if err != nil {
			t.Fatal(err)
		}
		runtime.SetFinalizer(geoSiteState.Load(), func(*geoSiteCache) { close(retired) })
		ClearGeoSiteCache()
		return matcher
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		if !matcher.ApplyDomain("retained.invalid") {
			t.Fatal("retained matcher changed")
		}
		select {
		case <-retired:
			runtime.KeepAlive(matcher)
			return
		default:
			time.Sleep(time.Millisecond)
		}
	}
	runtime.KeepAlive(matcher)
	t.Fatal("matcher retained retired raw cache generation")
}

func TestGeoSiteMatcherConstructionFailureIsNotCached(t *testing.T) {
	generationTestFixture(t, func(string) ([]*router.Domain, error) {
		return []*router.Domain{{Type: router.Domain_Type(999), Value: "unknown.invalid"}}, nil
	})
	SetSiteMatcher("mph")
	if _, err := LoadGeoSiteMatcher("unknown"); err == nil {
		t.Fatal("MPH accepted an unsupported domain type")
	}
	// The legacy succinct builder ignores unknown domain types. Switching the
	// builder without Clear must not recover an error cached by the failed build.
	SetSiteMatcher("succinct")
	if matcher, err := LoadGeoSiteMatcher("unknown"); err != nil || matcher == nil {
		t.Fatal("matcher construction failure retained", err)
	}
}
