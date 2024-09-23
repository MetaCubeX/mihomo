package tunnel

import (
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
)

type TunnelStatus int

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

// UnmarshalYAML unserialize Status with yaml
func (s *TunnelStatus) UnmarshalYAML(unmarshal func(any) error) error {
	var tp string
	unmarshal(&tp)
	status, exist := StatusMapping[strings.ToLower(tp)]
	if !exist {
		return errors.New("invalid status")
	}
	*s = status
	return nil
}

// UnmarshalJSON unserialize Status
func (s *TunnelStatus) UnmarshalJSON(data []byte) error {
	var tp string
	json.Unmarshal(data, &tp)
	status, exist := StatusMapping[strings.ToLower(tp)]
	if !exist {
		return errors.New("invalid status")
	}
	*s = status
	return nil
}

// UnmarshalText unserialize Status
func (s *TunnelStatus) UnmarshalText(data []byte) error {
	status, exist := StatusMapping[strings.ToLower(string(data))]
	if !exist {
		return errors.New("invalid status")
	}
	*s = status
	return nil
}

// MarshalYAML serialize TunnelMode with yaml
func (s TunnelStatus) MarshalYAML() (any, error) {
	return s.String(), nil
}

// MarshalJSON serialize Status
func (s TunnelStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
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

type AtomicStatus struct {
	value atomic.Int32
}

func (a *AtomicStatus) Store(s TunnelStatus) {
	a.value.Store(int32(s))
}

func (a *AtomicStatus) Load() TunnelStatus {
	return TunnelStatus(a.value.Load())
}

func (a *AtomicStatus) String() string {
	return a.Load().String()
}

func newAtomicStatus(s TunnelStatus) *AtomicStatus {
	a := &AtomicStatus{}
	a.Store(s)
	return a
}
