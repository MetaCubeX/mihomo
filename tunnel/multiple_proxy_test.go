package tunnel

import (
	"testing"

	"github.com/stretchr/testify/assert"

	C "github.com/metacubex/mihomo/constant"
	// aliased: tunnel.go declares a package-level `rules []C.Rule` variable.
	rulepkg "github.com/metacubex/mihomo/rules"
)

// testProxy is a minimal C.Proxy stand-in.
//
// The brief's test constructed real proxies via adapter.NewProxy(outbound.NewDirect()),
// but that cannot compile here: an in-package test of `tunnel` importing
// adapter/outbound creates an import cycle (outbound -> dns -> tunnel).
// Embedding C.Proxy promotes the full interface so testProxy satisfies it, and
// the assertions below only compare pointer identity, so no method is ever called.
type testProxy struct {
	C.Proxy
	name string
}

func (p *testProxy) Name() string { return p.name }

func newTestProxy(name string) C.Proxy { return &testProxy{name: name} }

func TestEffectiveMode(t *testing.T) {
	oldMode := mode
	defer func() { mode = oldMode }()
	mode = Rule

	assert.Equal(t, Rule, effectiveMode(&C.Metadata{}))
	assert.Equal(t, Global, effectiveMode(&C.Metadata{SpecialMode: "global"}))
	assert.Equal(t, Direct, effectiveMode(&C.Metadata{SpecialMode: "direct"}))
	assert.Equal(t, Rule, effectiveMode(&C.Metadata{SpecialMode: "bogus"})) // invalid → global
}

func TestFallbackProxy(t *testing.T) {
	oldProxies := proxies
	defer func() { proxies = oldProxies }()
	direct := newTestProxy("DIRECT")
	global := newTestProxy("GLOBAL")
	proxies = map[string]C.Proxy{"DIRECT": direct, "GLOBAL": global, "MP-0-group": direct}

	assert.Same(t, direct, fallbackProxy(&C.Metadata{SpecialFallbackProxy: "MP-0-group"}))
	assert.Same(t, global, fallbackProxy(&C.Metadata{}))                              // unset → GLOBAL
	assert.Same(t, global, fallbackProxy(&C.Metadata{SpecialFallbackProxy: "nope"})) // missing → GLOBAL
}

func TestApplyFallback(t *testing.T) {
	oldProxies := proxies
	defer func() { proxies = oldProxies }()
	direct := newTestProxy("DIRECT")
	proxies = map[string]C.Proxy{"DIRECT": direct, "GLOBAL": direct}

	md := &C.Metadata{SpecialFallbackProxy: "GLOBAL"}
	realRule, parseErr := rulepkg.ParseRule("DOMAIN-SUFFIX", "x.com", "DIRECT", nil, nil)
	assert.NoError(t, parseErr)
	assert.NotNil(t, realRule)
	// rule matched → untouched
	p, r, err := applyFallback(direct, realRule, nil, md)
	assert.Same(t, direct, p)
	assert.NotNil(t, r)
	assert.NoError(t, err)
	// no rule matched (nil rule) → fallback applied
	p, r, err = applyFallback(direct, nil, nil, md)
	assert.Same(t, direct, p)
	assert.Nil(t, r)
	assert.NoError(t, err)
}
