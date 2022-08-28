package dialer

import (
	"go.uber.org/atomic"
)

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
	network       int
	prefer        int
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

func WithPreferIPv4() Option {
	return func(opt *option) {
		opt.prefer = 4
	}
}

func WithPreferIPv6() Option {
	return func(opt *option) {
		opt.prefer = 6
	}
}

func WithOnlySingleStack(isIPv4 bool) Option {
	return func(opt *option) {
		if isIPv4 {
			opt.network = 4
		} else {
			opt.network = 6
		}
	}
}
