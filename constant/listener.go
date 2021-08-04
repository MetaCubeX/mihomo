package constant

type Listener interface {
	RawAddress() string
	Address() string
	Close() error
}
