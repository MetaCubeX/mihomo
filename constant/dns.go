package constant

import (
	"encoding/json"
	"errors"
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
)

type DNSMode int

// UnmarshalYAML unserialize EnhancedMode with yaml
func (e *DNSMode) UnmarshalYAML(unmarshal func(any) error) error {
	var tp string
	if err := unmarshal(&tp); err != nil {
		return err
	}
	mode, exist := DNSModeMapping[tp]
	if !exist {
		return errors.New("invalid mode")
	}
	*e = mode
	return nil
}

// MarshalYAML serialize EnhancedMode with yaml
func (e DNSMode) MarshalYAML() (any, error) {
	return e.String(), nil
}

// UnmarshalJSON unserialize EnhancedMode with json
func (e *DNSMode) UnmarshalJSON(data []byte) error {
	var tp string
	json.Unmarshal(data, &tp)
	mode, exist := DNSModeMapping[tp]
	if !exist {
		return errors.New("invalid mode")
	}
	*e = mode
	return nil
}

// MarshalJSON serialize EnhancedMode with json
func (e DNSMode) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

func (e DNSMode) String() string {
	switch e {
	case DNSNormal:
		return "normal"
	case DNSFakeIP:
		return "fake-ip"
	case DNSMapping:
		return "redir-host"
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
