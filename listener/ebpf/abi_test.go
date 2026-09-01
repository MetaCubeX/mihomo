package ebpf

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestABILayoutV1(t *testing.T) {
	c := abiCLayout()
	require.EqualValues(t, unsafe.Sizeof(DaeParam{}), c.param)
	require.EqualValues(t, unsafe.Sizeof(RedirectTuple{}), c.tuple)
	require.EqualValues(t, unsafe.Sizeof(RedirectEntry{}), c.redirect)
	require.EqualValues(t, unsafe.Sizeof(DirectTrackEntry{}), c.direct)
	require.EqualValues(t, unsafe.Sizeof(Event{}), c.event)
	require.EqualValues(t, unsafe.Offsetof(DaeParam{}.DAESocketMark), c.paramSocketMark)
	require.EqualValues(t, unsafe.Offsetof(Event{}.DestIP), c.eventDestIP)
	require.EqualValues(t, unsafe.Offsetof(Event{}.SourcePort), c.eventSourcePort)
	require.EqualValues(t, 44, unsafe.Sizeof(DaeParam{}))
	require.EqualValues(t, 20, unsafe.Offsetof(DaeParam{}.DAESocketMark))
	require.EqualValues(t, 40, unsafe.Sizeof(RedirectTuple{}))
	require.EqualValues(t, 20, unsafe.Sizeof(RedirectEntry{}))
	require.EqualValues(t, 16, unsafe.Sizeof(DirectTrackEntry{}))
	require.EqualValues(t, 72, unsafe.Sizeof(Event{}))
	require.EqualValues(t, 52, unsafe.Offsetof(Event{}.DestIP))
	require.EqualValues(t, 68, unsafe.Offsetof(Event{}.SourcePort))
}

func TestABIMapV1(t *testing.T) {
	maps := make(map[string]MapSpec, len(ABIMaps))
	for _, spec := range ABIMaps {
		maps[spec.Name] = spec
	}
	for name, want := range map[string]MapSpec{
		"DAE_PARAM":               {Type: "array", MaxEntries: 1, KeySize: 4, ValueSize: unsafe.Sizeof(DaeParam{})},
		"DYNAMIC_BYPASS_DST_IPS":  {Type: "lru_hash", MaxEntries: 16384, KeySize: 4, ValueSize: 1},
		"DYNAMIC_BYPASS_DST_IP6S": {Type: "lru_hash", MaxEntries: 4096, KeySize: 16, ValueSize: 1},
		"REDIRECT_TRACK":          {Type: "lru_hash", MaxEntries: 32768, KeySize: unsafe.Sizeof(RedirectTuple{}), ValueSize: unsafe.Sizeof(RedirectEntry{})},
		"DIRECT_TRACK":            {Type: "lru_hash", MaxEntries: 65536, KeySize: unsafe.Sizeof(RedirectTuple{}), ValueSize: unsafe.Sizeof(DirectTrackEntry{})},
		"LISTEN_SOCKET_MAP":       {Type: "sockmap", MaxEntries: 4, KeySize: 4, ValueSize: 4},
		"EVENT_RINGBUF":           {Type: "ringbuf", MaxEntries: 262144},
	} {
		got, ok := maps[name]
		require.True(t, ok, name)
		require.Equal(t, want.Type, got.Type, name)
		require.Equal(t, want.MaxEntries, got.MaxEntries, name)
		require.Equal(t, want.KeySize, got.KeySize, name)
		require.Equal(t, want.ValueSize, got.ValueSize, name)
	}
	require.Equal(t, uint32(1), ABIVersion)
	require.Equal(t, uint32(0x1dae), TPROXYMark)
	require.Equal(t, uint32(0x2dae), BypassMark)
}
