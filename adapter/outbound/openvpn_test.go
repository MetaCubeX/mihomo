package outbound

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestOpenVPNTransitionWindowPresence(t *testing.T) {
	window, set, err := openVPNTransitionWindow(nil)
	if err != nil || set || window != 0 {
		t.Fatalf("omitted tran-window = (%v, %v, %v)", window, set, err)
	}
	zero := 0
	window, set, err = openVPNTransitionWindow(&zero)
	if err != nil || !set || window != 0 {
		t.Fatalf("explicit zero tran-window = (%v, %v, %v)", window, set, err)
	}
}

func TestOpenVPNRejectsTranWindowOverflow(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("overflow fixture requires 64-bit int")
	}
	maxSeconds := int64((time.Duration(1<<63 - 1)) / time.Second)
	overflow := int(maxSeconds + 1)
	_, err := NewOpenVPN(OpenVPNOption{TranWindow: &overflow})
	if err == nil || !strings.Contains(err.Error(), "tran-window is too large") {
		t.Fatalf("overflowing tran-window was not rejected: %v", err)
	}
}
