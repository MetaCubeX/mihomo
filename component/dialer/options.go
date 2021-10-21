package dialer

var DefaultOptions []Option

type config struct {
	skipDefault   bool
	interfaceName string
	addrReuse     bool
}

type Option func(opt *config)

func WithInterface(name string) Option {
	return func(opt *config) {
		opt.interfaceName = name
	}
}

func WithAddrReuse(reuse bool) Option {
	return func(opt *config) {
		opt.addrReuse = reuse
	}
}

func WithSkipDefault(skip bool) Option {
	return func(opt *config) {
		opt.skipDefault = skip
	}
}
