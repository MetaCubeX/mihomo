package constant

type Sniffer interface {
	SupportNetwork() NetWork
	SniffTCP(bytes []byte) (string, error)
	Protocol() string
}

const (
	TLS SnifferType = iota
)

var (
	SnifferList = []SnifferType{TLS}
)

type SnifferType int

func (rt SnifferType) String() string {
	switch rt {
	case TLS:
		return "TLS"
	default:
		return "Unknown"
	}
}
