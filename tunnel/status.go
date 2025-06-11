package tunnel

import (
	"errors"
	"strings"
)

type TunnelStatus int32

// StatusMapping is a mapping for Status enum
var StatusMapping = map[string]TunnelStatus{
	Suspend.String(): Suspend,
	Inner.String():   Inner,
	Running.String(): Running,
}

const (
	Suspend TunnelStatus = iota
	Inner
	Running
)

// UnmarshalText unserialize Status
func (s *TunnelStatus) UnmarshalText(data []byte) error {
	status, exist := StatusMapping[strings.ToLower(string(data))]
	if !exist {
		return errors.New("invalid status")
	}
	*s = status
	return nil
}

// MarshalText serialize Status
func (s TunnelStatus) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s TunnelStatus) String() string {
	switch s {
	case Suspend:
		return "suspend"
	case Inner:
		return "inner"
	case Running:
		return "running"
	default:
		return "Unknown"
	}
}
