package constant

// ProxySignal is used to handle graceful shutdown of proxy
type ProxySignal struct {
	Done   chan<- struct{}
	Closed <-chan struct{}
}
