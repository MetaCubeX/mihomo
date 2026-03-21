package pool

import "github.com/metacubex/sing/common/buf"

func init() {
	buf.DefaultAllocator = DefaultAllocator
}
