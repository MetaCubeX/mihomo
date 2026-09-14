package outbound

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestHysteria2ResetSessionBeforeAnyDial(t *testing.T) {
	h, err := NewHysteria2(Hysteria2Option{
		Name: "hy2", Server: "203.0.113.10", Port: 443, Password: "x",
	})
	if err != nil {
		t.Fatal(err)
	}
	var resetter C.SessionResetter = h
	// A client that never dialed has no session to discard; the reset must not
	// close the client for good, so a later dial can still connect.
	resetter.ResetSession("test")
	resetter.ResetSession("test")
	if h.client == nil {
		t.Fatal("ResetSession discarded the client itself")
	}
}

func TestResetSessionOnAnOutboundWithoutAClient(t *testing.T) {
	(&Hysteria{}).ResetSession("test")
	(&Tuic{}).ResetSession("test")
	(&Hysteria2{}).ResetSession("test")
}
