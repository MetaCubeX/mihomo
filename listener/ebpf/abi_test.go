package ebpf

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestABILayoutV2(t *testing.T) {
	require.EqualValues(t, 44, unsafe.Sizeof(DaeParam{}))
	require.EqualValues(t, 20, unsafe.Offsetof(DaeParam{}.DAESocketMark))
	require.EqualValues(t, 40, unsafe.Sizeof(RedirectTuple{}))
	require.EqualValues(t, 20, unsafe.Sizeof(RedirectEntry{}))
	require.EqualValues(t, 16, unsafe.Sizeof(FlowOwnerEntry{}))
	require.EqualValues(t, 72, unsafe.Sizeof(Event{}))
	require.EqualValues(t, 52, unsafe.Offsetof(Event{}.DestIP))
	require.EqualValues(t, 68, unsafe.Offsetof(Event{}.SourcePort))
}

func TestABIMapV2(t *testing.T) {
	maps := make(map[string]MapSpec, len(ABIMaps))
	for _, spec := range ABIMaps {
		maps[spec.Name] = spec
	}
	for name, want := range map[string]MapSpec{
		"DAE_PARAM":         {Type: "array", MaxEntries: 1, KeySize: 4, ValueSize: unsafe.Sizeof(DaeParam{})},
		"DYN_DIRECT4":       {Type: "lru_hash", MaxEntries: 16384, KeySize: 4, ValueSize: 1},
		"DYN_DIRECT6":       {Type: "lru_hash", MaxEntries: 4096, KeySize: 16, ValueSize: 1},
		"DYN_PROXY4":        {Type: "lru_hash", MaxEntries: 16384, KeySize: 4, ValueSize: 1},
		"DYN_PROXY6":        {Type: "lru_hash", MaxEntries: 4096, KeySize: 16, ValueSize: 1},
		"REDIRECT_TRACK":    {Type: "lru_hash", MaxEntries: 32768, KeySize: unsafe.Sizeof(RedirectTuple{}), ValueSize: unsafe.Sizeof(RedirectEntry{})},
		"FLOW_OWNER":        {Type: "lru_hash", MaxEntries: 65536, KeySize: unsafe.Sizeof(RedirectTuple{}), ValueSize: unsafe.Sizeof(FlowOwnerEntry{})},
		"LISTEN_SOCKET_MAP": {Type: "sockmap", MaxEntries: 4, KeySize: 4, ValueSize: 4},
		"EVENT_RINGBUF":     {Type: "ringbuf", MaxEntries: 262144},
	} {
		got, ok := maps[name]
		require.True(t, ok, name)
		require.Equal(t, want.Type, got.Type, name)
		require.Equal(t, want.MaxEntries, got.MaxEntries, name)
		require.Equal(t, want.KeySize, got.KeySize, name)
		require.Equal(t, want.ValueSize, got.ValueSize, name)
	}
	require.Equal(t, uint32(2), ABIVersion)
	require.Equal(t, uint32(0x1dae), TPROXYMark)
	require.Equal(t, uint32(0x2dae), BypassMark)
}
