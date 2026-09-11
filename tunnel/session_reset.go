package tunnel

import (
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// ResetOutboundSessions asks every outbound that keeps a long-lived transport
// session (C.SessionResetter) to drop it: the named proxies and every
// provider's proxies, each outbound once however many names carry it. Nothing
// is dialed here; the next connection through such an outbound handshakes
// anew. Returns how many outbounds were reset.
func ResetOutboundSessions(reason string) int {
	configMux.RLock()
	currentProxies, currentProviders := proxies, providers
	configMux.RUnlock()

	seen := make(map[C.SessionResetter]struct{})
	visit := func(proxy C.Proxy) {
		if proxy == nil {
			return
		}
		resetter, ok := proxy.Adapter().(C.SessionResetter)
		if !ok {
			return
		}
		if _, done := seen[resetter]; done {
			return
		}
		seen[resetter] = struct{}{}
		resetter.ResetSession(reason)
	}
	for _, proxy := range currentProxies {
		visit(proxy)
	}
	for _, provider := range currentProviders {
		for _, proxy := range provider.Proxies() {
			visit(proxy)
		}
	}
	if len(seen) > 0 {
		log.Infoln("[Tunnel] %s: reset %d outbound session(s)", reason, len(seen))
	}
	return len(seen)
}
