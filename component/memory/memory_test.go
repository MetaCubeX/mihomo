package memory

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemoryInfo(t *testing.T) {
	v, err := GetMemoryInfo(int32(os.Getpid()))
	if errors.Is(err, ErrNotImplementedError) {
		t.Skip("not implemented")
	}
	require.NoErrorf(t, err, "getting memory info error %v", err)
	empty := MemoryInfoStat{}
	if v == nil || *v == empty {
		t.Errorf("could not get memory info %v", v)
	} else {
		t.Logf("memory info {RSS:%s, VMS:%s}", PrettyByteSize(v.RSS), PrettyByteSize(v.VMS))
	}
}
