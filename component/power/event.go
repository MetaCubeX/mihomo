package power

type Type uint8

const (
	SUSPEND Type = iota
	RESUME
	RESUMEAUTOMATIC // Because the user is not present, most applications should do nothing.
)

func (t Type) String() string {
	switch t {
	case SUSPEND:
		return "SUSPEND"
	case RESUME:
		return "RESUME"
	case RESUMEAUTOMATIC:
		return "RESUMEAUTOMATIC"
	default:
		return ""
	}
}
