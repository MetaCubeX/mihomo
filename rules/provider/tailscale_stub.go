//go:build !with_gvisor || no_tailscale

package provider

import (
	"errors"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules/common"
)

func newTailscaleRuleProvider(name string, proxyName string, proxies map[string]C.Proxy, parse common.ParseRuleFunc) (P.RuleProvider, error) {
	return nil, errors.New("tailscale rule provider is not available in this build (requires the with_gvisor build tag without no_tailscale)")
}
