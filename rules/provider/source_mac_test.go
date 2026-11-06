package provider

import (
	"sync"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules/common"
)

// Exercise concurrent provider publication and all readers used by matching,
// the API and the source-MAC demand scanner.
func TestSourceMACStrategyPublication(t *testing.T) {
	with := &classicalStrategy{rules: []C.Rule{&common.SrcMAC{}}, count: 1}
	without := &classicalStrategy{}
	p := &baseProvider{strategy: without}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				p.NeedsSourceMAC()
				p.ProviderNames()
				p.Count()
				p.Strategy()
				p.Match(&C.Metadata{}, C.RuleMatchHelper{})
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		p.setStrategy(with)
		p.setStrategy(without)
	}
	wg.Wait()
	if p.NeedsSourceMAC() {
		t.Fatal("removed MAC requirement retained")
	}
	p.setStrategy(with)
	if !p.NeedsSourceMAC() {
		t.Fatal("new MAC requirement missing")
	}
}

func TestBaseProviderNilStrategyCount(t *testing.T) {
	p := &baseProvider{}
	if p.Count() != 0 {
		t.Fatal("expected 0 count for nil strategy")
	}
}
