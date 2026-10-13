package adapter

import (
	"context"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/require"
)

// A loopback target usually answers in well under a millisecond. The test
// cannot force that, so it repeats the measurement: every successful run must
// report a nonzero delay, since zero is what callers read as a failure.
func TestURLTestSubMillisecondDelay(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	unifiedDelay := UnifiedDelay.Load()
	defer UnifiedDelay.Store(unifiedDelay)

	for _, unified := range []bool{false, true} {
		UnifiedDelay.Store(unified)
		proxy := NewProxy(outbound.NewDirect())
		for i := 0; i < 20; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			delay, err := proxy.URLTest(ctx, server.URL, nil)
			cancel()
			require.NoError(t, err)
			require.NotZero(t, delay, "unified-delay: %t", unified)

			require.True(t, proxy.AliveForTestUrl(server.URL))
			require.Equal(t, delay, proxy.LastDelayForTestUrl(server.URL))
			history := proxy.DelayHistory()
			require.Equal(t, delay, history[len(history)-1].Delay)
		}
	}
}
