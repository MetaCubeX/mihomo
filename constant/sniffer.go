package constant

type Sniffer interface {
	SupportNetwork() NetWork
	SniffTCP(bytes []byte) (string, error)
	Protocol() string
}

const (
	TLS SnifferType = iota
        HTTP SnifferType
)

var (
	SnifferList = []SnifferType{TLS, HTTP}
)

type SnifferType int

func (rt SnifferType) String() string {
	switch rt {
	case TLS:
		return "TLS"
	case HTTP:
		return "HTTP"
	default:
		return "Unknown"
	}
}
