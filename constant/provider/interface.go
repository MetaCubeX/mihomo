package provider

import (
	"context"
	"fmt"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/constant"
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
	Read(ctx context.Context, oldHash utils.HashType) (buf []byte, hash utils.HashType, err error)
	Write(buf []byte) error
	Path() string
	Url() string
	Proxy() string
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
	Count() int
	// Touch is used to inform the provider that the proxy is actually being used while getting the list of proxies.
	// Commonly used in DialContext and DialPacketConn
	Touch()
	HealthCheck()
	Version() uint32
	RegisterHealthCheckTask(url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint)
	HealthCheckURL() string
	SetSubscriptionInfo(userInfo string)
}

// RuleProvider interface
type RuleProvider interface {
	Provider
	Behavior() RuleBehavior
	Count() int
	Match(*constant.Metadata) bool
	ShouldResolveIP() bool
	ShouldFindProcess() bool
	Strategy() any
}

// Rule Behavior
const (
	Domain RuleBehavior = iota
	IPCIDR
	Classical
)

// RuleBehavior defined
type RuleBehavior int

func (rt RuleBehavior) String() string {
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

func (rt RuleBehavior) Byte() byte {
	switch rt {
	case Domain:
		return 0
	case IPCIDR:
		return 1
	case Classical:
		return 2
	default:
		return 255
	}
}

func ParseBehavior(s string) (behavior RuleBehavior, err error) {
	switch s {
	case "domain":
		behavior = Domain
	case "ipcidr":
		behavior = IPCIDR
	case "classical":
		behavior = Classical
	default:
		err = fmt.Errorf("unsupported behavior type: %s", s)
	}
	return
}

const (
	YamlRule RuleFormat = iota
	TextRule
	MrsRule
)

type RuleFormat int

func (rf RuleFormat) String() string {
	switch rf {
	case YamlRule:
		return "YamlRule"
	case TextRule:
		return "TextRule"
	case MrsRule:
		return "MrsRule"
	default:
		return "Unknown"
	}
}

func ParseRuleFormat(s string) (format RuleFormat, err error) {
	switch s {
	case "", "yaml":
		format = YamlRule
	case "text":
		format = TextRule
	case "mrs":
		format = MrsRule
	default:
		err = fmt.Errorf("unsupported format type: %s", s)
	}
	return
}

type Tunnel interface {
	Providers() map[string]ProxyProvider
	RuleProviders() map[string]RuleProvider
	RuleUpdateCallback() *utils.Callback[RuleProvider]
}
