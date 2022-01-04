package ipstack

// TunAdapter hold the state of tun/tap interface
type TunAdapter interface {
	Close()
	Stack() string
	DnsHijack() []string
	AutoRoute() bool
}
