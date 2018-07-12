package tunnel

type Mode int

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
