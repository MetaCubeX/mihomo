package constant

import (
	"errors"
	"fmt"
	"strings"
)

// TUNInterceptMode selects how traffic is intercepted. Its zero value is vnic.
type TUNInterceptMode int

const (
	TunInterceptVNIC TUNInterceptMode = iota
	TunInterceptWFP
)

func (m *TUNInterceptMode) UnmarshalText(data []byte) error {
	switch strings.ToLower(string(data)) {
	case "vnic":
		*m = TunInterceptVNIC
	case "wfp":
		*m = TunInterceptWFP
	default:
		return fmt.Errorf("invalid tun intercept-mode: %q", data)
	}
	return nil
}

func (m TUNInterceptMode) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

func (m TUNInterceptMode) String() string {
	switch m {
	case TunInterceptVNIC:
		return "vnic"
	case TunInterceptWFP:
		return "wfp"
	default:
		return "unknown"
	}
}

var StackTypeMapping = map[string]TUNStack{
	strings.ToLower(TunGvisor.String()): TunGvisor,
	strings.ToLower(TunSystem.String()): TunSystem,
	strings.ToLower(TunMixed.String()):  TunMixed,
	strings.ToLower(TunMips.String()):   TunMips,
}

const (
	TunGvisor TUNStack = iota
	TunSystem
	TunMixed
	TunMips
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
	case TunMips:
		return "Mips"
	default:
		return "unknown"
	}
}
