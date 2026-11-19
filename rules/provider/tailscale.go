//go:build with_gvisor && !no_tailscale

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/rules/common"
)

type tailscaleRuleProvider struct {
	baseProvider
	name      string
	proxyName string
	source    P.TailscaleRouteSource
	updateAt  time.Time

	mu   sync.RWMutex
	ctx  context.Context
	stop context.CancelFunc
}

func (tp *tailscaleRuleProvider) Name() string {
	return tp.name
}

func (tp *tailscaleRuleProvider) VehicleType() P.VehicleType {
	return P.Tailscale
}

func (tp *tailscaleRuleProvider) Match(metadata *C.Metadata, helper C.RuleMatchHelper) bool {
	tp.mu.RLock()
	strategy := tp.strategy
	tp.mu.RUnlock()
	return strategy != nil && strategy.Match(metadata, helper)
}

func (tp *tailscaleRuleProvider) Count() int {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	if tp.strategy == nil {
		return 0
	}
	return tp.strategy.Count()
}

func (tp *tailscaleRuleProvider) Strategy() any {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return tp.strategy
}

// refresh rebuilds the matching strategy from the tailnet's current route set.
func (tp *tailscaleRuleProvider) refresh() error {
	ctx, cancel := context.WithTimeout(tp.ctx, 15*time.Second)
	defer cancel()
	routes, err := tp.source.RouteSet(ctx)
	if err != nil {
		return err
	}
	strategy := NewIPCidrStrategy()
	strategy.Reset()
	for _, prefix := range routes {
		strategy.Insert(prefix.String())
	}
	strategy.FinishInsert()

	tp.mu.Lock()
	tp.strategy = strategy
	tp.updateAt = time.Now()
	tp.mu.Unlock()

	if tunnel != nil {
		tunnel.RuleUpdateCallback().Emit(tp)
	}
	return nil
}

func (tp *tailscaleRuleProvider) Initial() error {
	if err := tp.refresh(); err != nil {
		return err
	}
	go func() {
		for range tp.source.WatchRouteSet(tp.ctx) {
			if err := tp.refresh(); err != nil {
				log.Warnln("[Tailscale] rule provider [%s] refresh failed: %v", tp.name, err)
			}
		}
	}()
	return nil
}

func (tp *tailscaleRuleProvider) Update() error {
	return tp.refresh()
}

func (tp *tailscaleRuleProvider) MarshalJSON() ([]byte, error) {
	tp.mu.RLock()
	count := 0
	if tp.strategy != nil {
		count = tp.strategy.Count()
	}
	updateAt := tp.updateAt
	tp.mu.RUnlock()
	return json.Marshal(
		providerForApi{
			Behavior:    tp.behavior.String(),
			Name:        tp.name,
			RuleCount:   count,
			Type:        tp.Type().String(),
			VehicleType: tp.VehicleType().String(),
			UpdatedAt:   updateAt,
		})
}

func (tp *tailscaleRuleProvider) Close() error {
	tp.stop()
	runtime.SetFinalizer(tp, nil)
	return nil
}

// newTailscaleRuleProvider creates a rule provider whose content mirrors the
// tailnet route set of the referenced tailscale outbound.
func newTailscaleRuleProvider(name string, proxyName string, proxies map[string]C.Proxy, parse common.ParseRuleFunc) (P.RuleProvider, error) {
	if proxyName == "" {
		return nil, errors.New("tailscale rule provider requires `proxy`, the name of a tailscale outbound")
	}
	proxy, ok := proxies[proxyName]
	if !ok {
		return nil, fmt.Errorf("tailscale rule provider: proxy [%s] not found", proxyName)
	}

	// Reach through wrapper layers (e.g. the auto-close adapter) until we find
	// the concrete tailscale outbound.
	var source P.TailscaleRouteSource
	adapter := proxy.Adapter()
	for adapter != nil {
		if ts, ok := adapter.(P.TailscaleRouteSource); ok {
			source = ts
			break
		}
		u, ok := adapter.(interface {
			UnwrapProxyAdapter() C.ProxyAdapter
		})
		if !ok {
			break
		}
		adapter = u.UnwrapProxyAdapter()
	}
	if source == nil {
		return nil, fmt.Errorf("tailscale rule provider: proxy [%s] is not a tailscale outbound", proxyName)
	}

	ctx, cancel := context.WithCancel(context.Background())
	strategy := NewIPCidrStrategy()
	strategy.Reset()
	tp := &tailscaleRuleProvider{
		baseProvider: baseProvider{
			behavior: P.IPCIDR,
			strategy: strategy,
		},
		name:      name,
		proxyName: proxyName,
		source:    source,
		updateAt:  time.Now(),
		ctx:       ctx,
		stop:      cancel,
	}

	wrapper := &TailscaleRuleProvider{tp}
	runtime.SetFinalizer(wrapper, (*TailscaleRuleProvider).Close)
	return wrapper, nil
}

type TailscaleRuleProvider struct {
	*tailscaleRuleProvider
}

func (tp *TailscaleRuleProvider) Close() error {
	return tp.tailscaleRuleProvider.Close()
}
