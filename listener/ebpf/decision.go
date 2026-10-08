package ebpf

import (
	"net/netip"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// ConservativeFallbackTTL is intentionally short. DNS callers that know the
// authoritative record TTL should call Observe directly; a routing observer
// must never manufacture a long-lived bypass entry from a connection alone.
const ConservativeFallbackTTL = time.Minute

// DecisionObserver converts Mihomo's completed outbound selection into a
// future-flow policy observation. It never writes FLOW_OWNER: this callback
// commonly runs after the current TCP flow has already reached Mihomo and an
// accepted socket cannot safely be migrated to the kernel direct datapath.
func DecisionObserver(offloader *Offloader, fallbackTTL time.Duration) func(*C.Metadata, C.Proxy) {
	if fallbackTTL <= 0 {
		fallbackTTL = ConservativeFallbackTTL
	}
	return func(metadata *C.Metadata, proxy C.Proxy) {
		if offloader == nil || metadata == nil || !metadata.DstIP.IsValid() || proxy == nil {
			return
		}
		domain := metadata.Host
		if domain == "" {
			domain = metadata.DstIP.String() // IP-only rules have a proven destination.
		}
		action := Proxy
		if proxy.Type() == C.Direct {
			action = Direct
		}
		_ = offloader.Observe(domain, []netip.Addr{metadata.DstIP}, fallbackTTL, action)
	}
}
