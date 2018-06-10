package constant

// Socks addr type
const (
	AtypIPv4       = 1
	AtypDomainName = 3
	AtypIPv6       = 4
)

// Addr is used to store connection address
type Addr struct {
	AddrType int
	Host     string
	Port     string
}
