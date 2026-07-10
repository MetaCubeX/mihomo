package tailnet

import (
	"reflect"
	"testing"
)

func TestNormalizeSearchDomains(t *testing.T) {
	got := NormalizeSearchDomains([]string{
		" TailB2B774.TS.NET. ",
		"tailb2b774.ts.net",
		"",
		"~.",
	})
	want := []string{"tailb2b774.ts.net"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeSearchDomains() = %v, want %v", got, want)
	}
}

func TestMagicDNSSearchDomainRegistry(t *testing.T) {
	const (
		proxyA = "magicdns-test-a"
		proxyB = "magicdns-test-b"
	)
	RemoveSearchDomains(proxyA)
	RemoveSearchDomains(proxyB)
	t.Cleanup(func() {
		RemoveSearchDomains(proxyA)
		RemoveSearchDomains(proxyB)
	})

	SetSearchDomains(proxyA, []string{"tailnet.test."})
	SetSearchDomains(proxyB, []string{"dept.tailnet.test"})

	if got, ok := ProxyNameForDomain("newvbox.tailnet.test."); !ok || got != proxyA {
		t.Fatalf("ProxyNameForDomain tailnet = %q, %v", got, ok)
	}
	if got, ok := ProxyNameForDomain("newvbox.dept.tailnet.test."); !ok || got != proxyB {
		t.Fatalf("ProxyNameForDomain longest suffix = %q, %v", got, ok)
	}
	if got, ok := ProxyNameForDomain("example.invalid."); ok || got != "" {
		t.Fatalf("ProxyNameForDomain unrelated = %q, %v", got, ok)
	}
}
