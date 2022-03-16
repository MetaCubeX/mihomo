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
