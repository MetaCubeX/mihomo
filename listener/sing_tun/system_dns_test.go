package sing_tun

import (
	"reflect"
	"testing"
)

func TestSystemDNSSearchDomainArgs(t *testing.T) {
	got := systemDNSSearchDomainArgs("Meta", []string{
		" TailB2B774.TS.NET. ",
		"tailb2b774.ts.net",
		"",
	})
	want := []string{"domain", "Meta", "~.", "tailb2b774.ts.net"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("systemDNSSearchDomainArgs() = %v, want %v", got, want)
	}
}
