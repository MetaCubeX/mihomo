package constant

import (
	"errors"
	"strings"
)

var StackTypeMapping = map[string]TUNStack{
	strings.ToLower(TunGvisor.String()): TunGvisor,
	strings.ToLower(TunSystem.String()): TunSystem,
	strings.ToLower(TunMixed.String()):  TunMixed,
}

const (
	TunGvisor TUNStack = iota
	TunSystem
	TunMixed
)

type TUNStack int

// UnmarshalText unserialize TUNStack
func (e *TUNStack) UnmarshalText(data []byte) error {
	mode, exist := StackTypeMapping[strings.ToLower(string(data))]
	if !exist {
		return errors.New("invalid tun stack")
	}
	*e = mode
	return nil
}

// MarshalText serialize TUNStack with json
func (e TUNStack) MarshalText() ([]byte, error) {
	return []byte(e.String()), nil
}

func (e TUNStack) String() string {
	switch e {
	case TunGvisor:
		return "gVisor"
	case TunSystem:
		return "System"
	case TunMixed:
		return "Mixed"
	default:
		return "unknown"
	}
}
