package buf

import (
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
)

type Buffer = buf.Buffer

var StackNewSize = buf.StackNewSize
var KeepAlive = common.KeepAlive

//go:norace
func Dup[T any](obj T) T {
	return common.Dup(obj)
}

var Must = common.Must
var Error = common.Error
