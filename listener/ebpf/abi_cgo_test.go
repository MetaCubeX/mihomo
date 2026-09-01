//go:build cgo

package ebpf

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestCAndGoABILayoutV1(t *testing.T) {
	c := abiCLayout()
	require.EqualValues(t, unsafe.Sizeof(DaeParam{}), c.param)
	require.EqualValues(t, unsafe.Sizeof(RedirectTuple{}), c.tuple)
	require.EqualValues(t, unsafe.Sizeof(RedirectEntry{}), c.redirect)
	require.EqualValues(t, unsafe.Sizeof(DirectTrackEntry{}), c.direct)
	require.EqualValues(t, unsafe.Sizeof(Event{}), c.event)
	require.EqualValues(t, unsafe.Offsetof(DaeParam{}.DAESocketMark), c.paramSocketMark)
	require.EqualValues(t, unsafe.Offsetof(Event{}.DestIP), c.eventDestIP)
	require.EqualValues(t, unsafe.Offsetof(Event{}.SourcePort), c.eventSourcePort)
}
