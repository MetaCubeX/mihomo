package rules

import (
	"errors"
	"testing"

	"github.com/metacubex/mihomo/component/neighbor"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	RP "github.com/metacubex/mihomo/rules/provider"
)

func TestSourceMACParsing(t *testing.T) {
	if !neighbor.Supported {
		_, err := ParseRule("SRC-MAC", "02:00:00:00:AB:CD", "DIRECT", nil, nil)
		if !errors.Is(err, neighbor.ErrUnsupported) {
			t.Fatal("unsupported platform not rejected", err)
		}
		return
	}
	for _, s := range []string{"02:00:00:00:AB:CD", "02-00-00-00-ab-cd", "0200.0000.abcd"} {
		r, err := ParseRule("SRC-MAC", s, "DIRECT", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if r.Payload() != "02:00:00:00:ab:cd" || r.RuleType() != C.SrcMAC || !C.NeedsSourceMAC(r) {
			t.Fatal("invalid rule", r)
		}
		for _, mac := range []string{"", "02:00:00:00:ab:ce", "02:00:00:00:ab:cd"} {
			matched, adapter := r.Match(&C.Metadata{SrcMAC: mac}, C.RuleMatchHelper{})
			if matched != (mac == r.Payload()) || adapter != "DIRECT" {
				t.Fatal("wrong match", mac, matched)
			}
		}
	}
	for _, s := range []string{"", "not-a-mac", "02:00:00:00:00", "02:00:00:00:00:00:00:01", "02:00:00:00:00:gg"} {
		if _, err := ParseRule("SRC-MAC", s, "DIRECT", nil, nil); err == nil {
			t.Fatal("accepted invalid MAC", s)
		}
	}
}

func TestSourceMACLogicAndClassical(t *testing.T) {
	if !neighbor.Supported {
		t.Skip("no source MAC backend")
	}
	for _, tc := range []struct {
		kind, payload string
		want          bool
		lookups       int
	}{
		{"AND", "((NETWORK,UDP),(SRC-MAC,02:00:00:00:00:01))", false, 0},
		{"OR", "((NETWORK,TCP),(SRC-MAC,02:00:00:00:00:01))", true, 0},
		{"NOT", "((SRC-MAC,02:00:00:00:00:01))", true, 1},
		{"AND", "((NETWORK,TCP),(SRC-MAC,02:00:00:00:00:01))", false, 1},
	} {
		r, err := ParseRule(tc.kind, tc.payload, "DIRECT", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		matched, _ := r.Match(&C.Metadata{NetWork: C.TCP}, C.RuleMatchHelper{FindSourceMAC: func() { calls++ }})
		if matched != tc.want || calls != tc.lookups || !C.NeedsSourceMAC(r) {
			t.Fatalf("%s: matched %v, calls %d", tc.kind, matched, calls)
		}
	}
	p := RP.NewInlineProvider("devices", P.Classical, []string{"SRC-MAC,02:00:00:00:00:01", "AND,((NETWORK,UDP),(SRC-MAC,02:00:00:00:00:02))"}, ParseRule)
	if p.Count() != 2 || !p.(interface{ NeedsSourceMAC() bool }).NeedsSourceMAC() {
		t.Fatal("classical rules lost")
	}
	if !p.Match(&C.Metadata{SrcMAC: "02:00:00:00:00:01"}, C.RuleMatchHelper{}) {
		t.Fatal("classical source MAC did not match")
	}
}
