package tunnel

import (
	"context"
	"fmt"

	C "github.com/metacubex/mihomo/constant"
)

// ResolveRematch resolves a rematch selected by proxy before an internal URL
// test dials it. Ordinary proxies retain their normal dialing path. Rematching
// applies rules regardless of the tunnel mode, since the test explicitly chose
// the initial proxy rather than asking the tunnel to choose one.
func ResolveRematch(ctx context.Context, proxy C.Proxy, metadata *C.Metadata) (C.Proxy, error) {
	rematch := unwrapRematch(proxy, metadata)
	if rematch == nil {
		return proxy, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	metadata.Type = C.INNER
	conn, err := rematch.DialContext(ctx, metadata) // only updates routing metadata
	if conn != nil {
		_ = conn.Close()
	}
	if err != nil {
		return nil, err
	}
	proxy, _, err = match(metadata, ruleMatchHelper(ctx, metadata))
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if proxy == nil {
		return nil, fmt.Errorf("rematch %s did not resolve to a proxy", rematch.Name())
	}
	// The matcher returns a rematch adapter when it detects a routing cycle.
	// That adapter's noop connection must not be used for an HTTP test.
	if rematch := unwrapRematch(proxy, metadata); rematch != nil {
		return nil, fmt.Errorf("rematch cycle detected on %s", rematch.Name())
	}
	return proxy, nil
}

func unwrapRematch(proxy C.Proxy, metadata *C.Metadata) C.Proxy {
	for proxy != nil {
		if proxy.Type() == C.Rematch {
			return proxy
		}
		proxy = proxy.Unwrap(metadata, false)
	}
	return nil
}
