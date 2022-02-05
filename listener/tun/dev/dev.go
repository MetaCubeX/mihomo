package dev

// TunDevice is cross-platform tun interface
type TunDevice interface {
	Name() string
	URL() string
	MTU() (int, error)
	IsClose() bool
	Close() error
	Read(buff []byte) (int, error)
	Write(buff []byte) (int, error)
}
