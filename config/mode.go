package config

type Mode int

var (
	// ModeMapping is a mapping for Mode enum
	ModeMapping = map[string]Mode{
		"Global": Global,
		"Rule":   Rule,
		"Direct": Direct,
	}
)

const (
	Global Mode = iota
	Rule
	Direct
)

func (m Mode) String() string {
	switch m {
	case Global:
		return "Global"
	case Rule:
		return "Rule"
	case Direct:
		return "Direct"
	default:
		return "Unknow"
	}
}
