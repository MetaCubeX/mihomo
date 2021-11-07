package dialer

import "go.uber.org/atomic"

var (
	DefaultOptions   []Option
	DefaultInterface = atomic.NewString("")
)

type option struct {
	interfaceName string
	addrReuse     bool
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
