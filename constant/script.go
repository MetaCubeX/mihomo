package constant

type JSRuleMetadata struct {
	Type        string `json:"type"`
	Network     string `json:"network"`
	Host        string `json:"host"`
	SrcIP       string `json:"srcIP"`
	DstIP       string `json:"dstIP"`
	SrcPort     string `json:"srcPort"`
	DstPort     string `json:"dstPort"`
	Uid         *int32 `json:"uid"`
	Process     string `json:"process"`
	ProcessPath string `json:"processPath"`
}

type DnsType int

const (
	IPv4 = 1 << iota
	IPv6
	All
)

type JSFunction interface {
	//Resolve host to ip  by Clash DNS
	Resolve(host string, resolveType DnsType) []string
}
