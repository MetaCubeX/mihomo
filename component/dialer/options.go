package dialer

import "go.uber.org/atomic"

var (
	DefaultOptions     []Option
	DefaultInterface   = atomic.NewString("")
	DefaultRoutingMark = atomic.NewInt32(0)
)

type option struct {
	interfaceName string
	addrReuse     bool
	routingMark   int
	direct        bool
}

type Option func(opt *option)

func WithInterface(name string) Option {
	return func(opt *option) {
		opt.interfaceName = name
	}
}

func WithAddrReuse(reuse bool) Option {
	return func(opt *option) {
		opt.addrReuse = reuse
	}
}

func WithRoutingMark(mark int) Option {
	return func(opt *option) {
		opt.routingMark = mark
	}
}

func WithDirect() Option {
	return func(opt *option) {
		opt.direct = true
	}
}
