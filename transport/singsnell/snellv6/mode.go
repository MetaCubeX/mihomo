package snellv6

import (
	E "github.com/metacubex/sing/common/exceptions"
)

type Mode int

const (
	ModeDefault Mode = iota
	ModeUnshaped
	ModeUnsafeRaw
)

func ParseMode(name string) (Mode, error) {
	switch name {
	case "", "default":
		return ModeDefault, nil
	case "unshaped":
		return ModeUnshaped, nil
	case "unsafe-raw":
		return ModeUnsafeRaw, nil
	default:
		return 0, E.New("snell: unknown v6 mode: ", name)
	}
}

func (m Mode) String() string {
	switch m {
	case ModeDefault:
		return "default"
	case ModeUnshaped:
		return "unshaped"
	case ModeUnsafeRaw:
		return "unsafe-raw"
	default:
		panic("snell: invalid v6 mode")
	}
}

const maxPayload = 0xffff
