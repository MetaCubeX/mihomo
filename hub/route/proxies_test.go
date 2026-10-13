package route

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/require"
)

// A loopback target usually answers in well under a millisecond; the delay
// route must report that as a success, not as 503.
func TestGetProxyDelaySubMillisecond(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	var proxy C.Proxy = adapter.NewProxy(outbound.NewDirect())
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodGet, "/proxies/DIRECT/delay?timeout=5000&url="+url.QueryEscape(server.URL), nil)
		req = req.WithContext(context.WithValue(req.Context(), CtxKeyProxy, proxy))
		rec := httptest.NewRecorder()
		getProxyDelay(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		var body struct {
			Delay uint16 `json:"delay"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		require.NotZero(t, body.Delay)
	}
}
