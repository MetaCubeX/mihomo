package buf

import (
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
)

const BufferSize = buf.BufferSize

type Buffer = buf.Buffer

var New = buf.New
var NewPacket = buf.NewPacket
var NewSize = buf.NewSize
var With = buf.With
var As = buf.As

var (
	Must  = common.Must
	Error = common.Error
)
