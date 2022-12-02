package pool

import "github.com/sagernet/sing/common/buf"

func init() {
	buf.DefaultAllocator = defaultAllocator
}
