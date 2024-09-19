package constant

import (
	"encoding/json"
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

// UnmarshalYAML unserialize EnhancedMode with yaml
func (e *DNSMode) UnmarshalYAML(unmarshal func(any) error) error {
	var tp string
	if err := unmarshal(&tp); err != nil {
		return err
	}
	mode, exist := DNSModeMapping[strings.ToLower(tp)]
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
	if err := json.Unmarshal(data, &tp); err != nil {
		return err
	}
	mode, exist := DNSModeMapping[strings.ToLower(tp)]
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

func (e FilterMode) MarshalYAML() (interface{}, error) {
	return e.String(), nil
}

func (e *FilterMode) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tp string
	if err := unmarshal(&tp); err != nil {
		return err
	}
	mode, exist := FilterModeMapping[strings.ToLower(tp)]
	if !exist {
		return errors.New("invalid mode")
	}
	*e = mode
	return nil
}

func (e FilterMode) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

func (e *FilterMode) UnmarshalJSON(data []byte) error {
	var tp string
	if err := json.Unmarshal(data, &tp); err != nil {
		return err
	}
	mode, exist := FilterModeMapping[strings.ToLower(tp)]
	if !exist {
		return errors.New("invalid mode")
	}
	*e = mode
	return nil
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
