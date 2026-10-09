package executor

import (
	"testing"

	"github.com/metacubex/mihomo/tunnel"
)

func TestUpdateGeneralTCPConnectTimeout(t *testing.T) {
	old := GetGeneral()
	t.Cleanup(func() { updateGeneral(old, false) })
	general := *old
	general.TCPConnectTimeout = 15000
	updateGeneral(&general, false)
	if GetGeneral().TCPConnectTimeout != 15000 || tunnel.TCPConnectTimeout().Milliseconds() != 15000 {
		t.Fatal("configuration reload did not apply the TCP connection budget")
	}
}
