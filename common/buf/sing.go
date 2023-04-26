package buf

import (
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
)

const BufferSize = buf.BufferSize

type Buffer = buf.Buffer

var New = buf.New
var NewSize = buf.NewSize
var StackNew = buf.StackNew
var StackNewSize = buf.StackNewSize
var With = buf.With
var As = buf.As

var KeepAlive = common.KeepAlive

//go:norace
func Dup[T any](obj T) T {
	return common.Dup(obj)
}

var (
	Must  = common.Must
	Error = common.Error
)
