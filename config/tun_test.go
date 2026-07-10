package config

import (
	"reflect"
	"testing"
)

func TestParseTunDNSSearchDomains(t *testing.T) {
	var general General
	err := parseTun(RawTun{
		Enable:           true,
		DNSHijack:        []string{"0.0.0.0:53"},
		DNSSearchDomains: []string{"tailb2b774.ts.net"},
	}, &DNS{}, &general)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"tailb2b774.ts.net"}
	if !reflect.DeepEqual(general.Tun.DNSSearchDomains, want) {
		t.Fatalf("DNSSearchDomains = %v, want %v", general.Tun.DNSSearchDomains, want)
	}
}
