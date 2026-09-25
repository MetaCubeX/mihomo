package route

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/tunnel"
)

func TestSourceMACConfigAPI(t *testing.T) {
	old := tunnel.SourceMACOptions()
	t.Cleanup(func() { _ = tunnel.SetSourceMACOptions(old.Probe, int(old.Timeout/time.Millisecond), old.Interfaces) })
	if err := tunnel.SetSourceMACOptions(false, 1000, nil); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		body       string
		status     int
		probe      bool
		timeout    int
		interfaces []string
	}{
		{body: `{"src-mac-probe":true}`, status: 204, probe: true, timeout: 1000},
		{body: `{"src-mac-timeout":750}`, status: 204, probe: true, timeout: 750},
		{body: `{"src-mac-probe":false,"src-mac-timeout":0}`, status: 400, probe: true, timeout: 750},
		{body: `{"src-mac-probe":false}`, status: 204, probe: false, timeout: 750},
		{body: `{"src-mac-interfaces":["br-lan","eth0"]}`, status: 204, probe: false, timeout: 750, interfaces: []string{"br-lan", "eth0"}},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("PATCH", "/", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		patchConfigs(w, r)
		if w.Code != tc.status {
			t.Fatalf("PATCH %s: %d %s", tc.body, w.Code, w.Body.String())
		}
		w = httptest.NewRecorder()
		getConfigs(w, httptest.NewRequest("GET", "/", nil))
		var got struct {
			Probe      bool     `json:"src-mac-probe"`
			Timeout    int      `json:"src-mac-timeout"`
			Interfaces []string `json:"src-mac-interfaces"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Probe != tc.probe || got.Timeout != tc.timeout || len(got.Interfaces) != len(tc.interfaces) {
			t.Fatalf("PATCH did not preserve omitted options or rejected update: %+v", got)
		}
	}
}
