package provider

import "C"
import (
	"github.com/Dreamacro/clash/component/trie"
	"github.com/Dreamacro/clash/constant"
)

// Vehicle Type
const (
	File VehicleType = iota
	HTTP
	Compatible
)

// VehicleType defined
type VehicleType int

func (v VehicleType) String() string {
	switch v {
	case File:
		return "File"
	case HTTP:
		return "HTTP"
	case Compatible:
		return "Compatible"
	default:
		return "Unknown"
	}
}

type Vehicle interface {
	Read() ([]byte, error)
	Path() string
	Type() VehicleType
}

// Provider Type
const (
	Proxy ProviderType = iota
	Rule
)

// ProviderType defined
type ProviderType int

func (pt ProviderType) String() string {
	switch pt {
	case Proxy:
		return "Proxy"
	case Rule:
		return "Rule"
	default:
		return "Unknown"
	}
}

// Provider interface
type Provider interface {
	Name() string
	VehicleType() VehicleType
	Type() ProviderType
	Initial() error
	Update() error
}

// ProxyProvider interface
type ProxyProvider interface {
	Provider
	Proxies() []constant.Proxy
	// ProxiesWithTouch is used to inform the provider that the proxy is actually being used while getting the list of proxies.
	// Commonly used in DialContext and DialPacketConn
	ProxiesWithTouch() []constant.Proxy
	HealthCheck()
}

// Rule Type
const (
	Domain RuleType = iota
	IPCIDR
	Classical
)

// RuleType defined
type RuleType int

func (rt RuleType) String() string {
	switch rt {
	case Domain:
		return "Domain"
	case IPCIDR:
		return "IPCIDR"
	case Classical:
		return "Classical"
	default:
		return "Unknown"
	}
}

// RuleProvider interface
type RuleProvider interface {
	Provider
	Behavior() RuleType
	Match(*constant.Metadata) bool
	ShouldResolveIP() bool
	AsRule(adaptor string) constant.Rule
}

var (
	ruleProviders = map[string]*RuleProvider{}
)

func RuleProviders() map[string]*RuleProvider {
	return ruleProviders
}

type ruleSetProvider struct {
	count          int
	DomainRules    *trie.DomainTrie
	IPCIDRRules    *trie.IpCidrTrie
	ClassicalRules []C.Rule
}

type RuleSetProvider struct {
	*ruleSetProvider
}
