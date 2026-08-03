package inbound

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnixRemoteAddrIsAllowed(t *testing.T) {
	require.True(t, IsRemoteAddrDisAllowed(&net.UnixAddr{Name: "/tmp/mihomo.sock", Net: "unix"}))
}
