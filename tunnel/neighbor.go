package tunnel

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/neighbor"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
)

var sourceMACResolver interface {
	SetEnabled(bool)
	Configure(neighbor.Options)
	Options() neighbor.Options
	Resolve(context.Context, int, netip.Addr) (neighbor.MAC, bool)
	Lookup(int, netip.Addr) (neighbor.MAC, bool)
} = neighbor.New(func(err error) {
	log.Warnln("[SRC-MAC] neighbor resolution: %v", err)
})

// Serialize configuration replacement, asynchronous provider notifications and
// shutdown. Never wait for the backend while holding configMux.
var sourceMACConfigMu sync.Mutex
var sourceMACClosed bool

func init() {
	ruleUpdateCallback.Register(func(P.RuleProvider) { RefreshSourceMAC() })
}

func needsSourceMAC(rs []C.Rule, subs map[string][]C.Rule, providers map[string]P.RuleProvider) bool {
	visited := make(map[string]bool)
	var visitProvider func(string) bool
	visitProvider = func(name string) bool {
		if visited[name] {
			return false
		}
		visited[name] = true
		p := providers[name]
		if p == nil {
			return false
		}
		if demand, ok := p.(interface{ NeedsSourceMAC() bool }); ok && demand.NeedsSourceMAC() {
			return true
		}
		if deps, ok := p.(interface{ ProviderNames() []string }); ok {
			for _, name := range deps.ProviderNames() {
				if visitProvider(name) {
					return true
				}
			}
		}
		return false
	}
	visitRules := func(rs []C.Rule) bool {
		for _, r := range rs {
			if w, ok := r.(C.RuleWrapper); ok && w.IsDisabled() {
				continue
			}
			if C.NeedsSourceMAC(r) {
				return true
			}
			for _, name := range r.ProviderNames() {
				if visitProvider(name) {
					return true
				}
			}
		}
		return false
	}
	if visitRules(rs) {
		return true
	}
	// An inbound can select a sub-rule directly through SpecialRules.
	for _, rs := range subs {
		if visitRules(rs) {
			return true
		}
	}
	return false
}

func refreshSourceMACLocked() {
	if sourceMACClosed {
		return
	}
	configMux.RLock()
	enabled := needsSourceMAC(rules, subRules, ruleProviders)
	configMux.RUnlock()
	sourceMACResolver.SetEnabled(enabled)
}

// RefreshSourceMAC re-evaluates the currently applied rules, including providers.
// It deliberately ignores the provider in an update notification: an old
// configuration may still have a notification queued after replacement.
func RefreshSourceMAC() {
	sourceMACConfigMu.Lock()
	defer sourceMACConfigMu.Unlock()
	refreshSourceMACLocked()
}

func ShutdownSourceMAC() {
	sourceMACConfigMu.Lock()
	defer sourceMACConfigMu.Unlock()
	sourceMACClosed = true
	sourceMACResolver.SetEnabled(false)
}

func sourceMACLookup(metadata *C.Metadata, lookup func(int, netip.Addr) (neighbor.MAC, bool)) func() {
	source := metadata.SrcIP
	attempted := metadata.Type == C.INNER
	return func() {
		if attempted {
			return
		}
		attempted = true
		metadata.SrcMAC = ""
		// Preserve the original source even while RULE-SET,src swaps the IPs.
		if mac, ok := lookup(0, source); ok {
			metadata.SrcMAC = mac.String()
		}
	}
}

// SetSourceMACOptions applies top-level options. Changes cancel outstanding
// recoveries so disabling probes takes effect without waiting for old deadlines.
func SetSourceMACOptions(probe bool, timeoutMS int, interfaces []string) error {
	if err := neighbor.ValidateTimeout(timeoutMS); err != nil {
		return err
	}
	sourceMACConfigMu.Lock()
	defer sourceMACConfigMu.Unlock()
	sourceMACResolver.Configure(neighbor.Options{
		Probe:      probe,
		Timeout:    time.Duration(timeoutMS) * time.Millisecond,
		Interfaces: interfaces,
	})
	return nil
}
func SourceMACOptions() neighbor.Options { return sourceMACResolver.Options() }
