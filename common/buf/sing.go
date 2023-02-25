package buf

import (
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
)

const BufferSize = buf.BufferSize

type Buffer = buf.Buffer

var New = buf.New
var StackNew = buf.StackNew
var StackNewSize = buf.StackNewSize
var With = buf.With

var KeepAlive = common.KeepAlive

//go:norace
func Dup[T any](obj T) T {
	return common.Dup(obj)
}

var Must = common.Must
var Error = common.Error
