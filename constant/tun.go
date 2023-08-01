package constant

import (
	"encoding/json"
	"errors"
	"strings"
)

var StackTypeMapping = map[string]TUNStack{
	strings.ToLower(TunGvisor.String()): TunGvisor,
	strings.ToLower(TunSystem.String()): TunSystem,
	strings.ToLower(TunLWIP.String()):   TunLWIP,
	strings.ToLower(TunMixed.String()):  TunMixed,
}

const (
	TunGvisor TUNStack = iota
	TunSystem
	TunLWIP
	TunMixed
)

type TUNStack int

// UnmarshalYAML unserialize TUNStack with yaml
func (e *TUNStack) UnmarshalYAML(unmarshal func(any) error) error {
	var tp string
	if err := unmarshal(&tp); err != nil {
		return err
	}
	mode, exist := StackTypeMapping[strings.ToLower(tp)]
	if !exist {
		return errors.New("invalid tun stack")
	}
	*e = mode
	return nil
}

// MarshalYAML serialize TUNStack with yaml
func (e TUNStack) MarshalYAML() (any, error) {
	return e.String(), nil
}

// UnmarshalJSON unserialize TUNStack with json
func (e *TUNStack) UnmarshalJSON(data []byte) error {
	var tp string
	json.Unmarshal(data, &tp)
	mode, exist := StackTypeMapping[strings.ToLower(tp)]
	if !exist {
		return errors.New("invalid tun stack")
	}
	*e = mode
	return nil
}

// MarshalJSON serialize TUNStack with json
func (e TUNStack) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

func (e TUNStack) String() string {
	switch e {
	case TunGvisor:
		return "gVisor"
	case TunSystem:
		return "System"
	case TunLWIP:
		return "LWIP"
	case TunMixed:
		return "Mixed"
	default:
		return "unknown"
	}
}
