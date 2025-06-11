package constant

import (
	"errors"
	"strings"
)

// DNSModeMapping is a mapping for EnhancedMode enum
var DNSModeMapping = map[string]DNSMode{
	DNSNormal.String():  DNSNormal,
	DNSFakeIP.String():  DNSFakeIP,
	DNSMapping.String(): DNSMapping,
}

const (
	DNSNormal DNSMode = iota
	DNSFakeIP
	DNSMapping
	DNSHosts
)

type DNSMode int

// UnmarshalText unserialize EnhancedMode
func (e *DNSMode) UnmarshalText(data []byte) error {
	mode, exist := DNSModeMapping[strings.ToLower(string(data))]
	if !exist {
		return errors.New("invalid mode")
	}
	*e = mode
	return nil
}

// MarshalText serialize EnhancedMode
func (e DNSMode) MarshalText() ([]byte, error) {
	return []byte(e.String()), nil
}

func (e DNSMode) String() string {
	switch e {
	case DNSNormal:
		return "normal"
	case DNSFakeIP:
		return "fake-ip"
	case DNSMapping:
		return "redir-host"
	case DNSHosts:
		return "hosts"
	default:
		return "unknown"
	}
}

type DNSPrefer int

const (
	DualStack DNSPrefer = iota
	IPv4Only
	IPv6Only
	IPv4Prefer
	IPv6Prefer
)

var dnsPreferMap = map[string]DNSPrefer{
	DualStack.String():  DualStack,
	IPv4Only.String():   IPv4Only,
	IPv6Only.String():   IPv6Only,
	IPv4Prefer.String(): IPv4Prefer,
	IPv6Prefer.String(): IPv6Prefer,
}

func (d DNSPrefer) String() string {
	switch d {
	case DualStack:
		return "dual"
	case IPv4Only:
		return "ipv4"
	case IPv6Only:
		return "ipv6"
	case IPv4Prefer:
		return "ipv4-prefer"
	case IPv6Prefer:
		return "ipv6-prefer"
	default:
		return "dual"
	}
}

func NewDNSPrefer(prefer string) DNSPrefer {
	if p, ok := dnsPreferMap[prefer]; ok {
		return p
	} else {
		return DualStack
	}
}

// FilterModeMapping is a mapping for FilterMode enum
var FilterModeMapping = map[string]FilterMode{
	FilterBlackList.String(): FilterBlackList,
	FilterWhiteList.String(): FilterWhiteList,
}

type FilterMode int

const (
	FilterBlackList FilterMode = iota
	FilterWhiteList
)

func (e FilterMode) String() string {
	switch e {
	case FilterBlackList:
		return "blacklist"
	case FilterWhiteList:
		return "whitelist"
	default:
		return "unknown"
	}
}

func (e FilterMode) MarshalText() ([]byte, error) {
	return []byte(e.String()), nil
}

func (e *FilterMode) UnmarshalText(data []byte) error {
	mode, exist := FilterModeMapping[strings.ToLower(string(data))]
	if !exist {
		return errors.New("invalid mode")
	}
	*e = mode
	return nil
}

type HTTPVersion string

const (
	// HTTPVersion11 is HTTP/1.1.
	HTTPVersion11 HTTPVersion = "http/1.1"
	// HTTPVersion2 is HTTP/2.
	HTTPVersion2 HTTPVersion = "h2"
	// HTTPVersion3 is HTTP/3.
	HTTPVersion3 HTTPVersion = "h3"
)
