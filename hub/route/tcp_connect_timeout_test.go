package route

import (
	"encoding/json"
	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"strings"
	"testing"

	"github.com/metacubex/chi"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"
)

func TestPatchTCPConnectTimeout(t *testing.T) {
	old := tunnel.TCPConnectTimeout().Milliseconds()
	t.Cleanup(func() { _ = tunnel.SetTCPConnectTimeout(old) })
	router := chi.NewRouter()
	router.Patch("/configs", patchConfigs)
	router.Get("/configs", getConfigs)
	for _, body := range []string{
		`{"tcp-connect-timeout":0}`,
		`{"tcp-connect-timeout":-1}`,
		`{"tcp-connect-timeout":9223372036854775807}`,
		`{"tcp-connect-timeout":1.5}`,
	} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodPatch, "/configs", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest || tunnel.TCPConnectTimeout().Milliseconds() != old {
			t.Fatalf("invalid PATCH %s: status=%d timeout=%v", body, w.Code, tunnel.TCPConnectTimeout())
		}
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPatch, "/configs", strings.NewReader(`{"tcp-connect-timeout":15000}`)))
	if w.Code != http.StatusNoContent || executor.GetGeneral().TCPConnectTimeout != 15000 {
		t.Fatalf("valid PATCH failed: status=%d timeout=%v", w.Code, tunnel.TCPConnectTimeout())
	}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/configs", nil))
	var general struct {
		TCPConnectTimeout int64 `json:"tcp-connect-timeout"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &general); err != nil || w.Code != http.StatusOK || general.TCPConnectTimeout != 15000 {
		t.Fatalf("GET did not return the effective timeout: status=%d body=%s err=%v", w.Code, w.Body.String(), err)
	}
}
