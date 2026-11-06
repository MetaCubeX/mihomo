package tunnel

import (
	"fmt"

	C "github.com/metacubex/mihomo/constant"
)

// ResolveICMP uses the same rules and group selection as TCP/UDP, without
// treating an echo identifier as a transport port or looking up a TCP process.
func (t tunnel) ResolveICMP(metadata *C.Metadata) (C.Proxy, error) {
	if !isHandle(metadata.Type) {
		return nil, fmt.Errorf("tunnel is not running")
	}
	metadata.NetWork = C.ICMP
	fixMetadata(metadata)
	if err := preHandleMetadata(metadata); err != nil {
		return nil, err
	}
	proxy, _, err := resolveMetadata(metadata)
	if err != nil {
		return nil, err
	}
	for depth := 0; proxy != nil && depth < 32; depth++ {
		next := proxy.Unwrap(metadata, true)
		if next == nil {
			return proxy, nil
		}
		proxy = next
	}
	return nil, fmt.Errorf("invalid ICMP proxy chain")
}
