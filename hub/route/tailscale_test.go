package route

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

type discoveryTestOutbound struct {
	outbound.ProxyAdapter
	query func(context.Context) (*C.TailscaleExitNodes, error)
}

func (o *discoveryTestOutbound) TailscaleExitNodes(ctx context.Context) (*C.TailscaleExitNodes, error) {
	return o.query(ctx)
}

func TestTailscaleExitNodesAPI(t *testing.T) {
	oldProxies, oldProviders := tunnel.Proxies(), tunnel.Providers()
	t.Cleanup(func() { tunnel.UpdateProxies(oldProxies, oldProviders) })
	calls := 0
	newOutbound := func(name, id string) *discoveryTestOutbound {
		return &discoveryTestOutbound{
			ProxyAdapter: outbound.NewBase(outbound.BaseOption{Name: name, Type: C.Tailscale}),
			query: func(ctx context.Context) (*C.TailscaleExitNodes, error) {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 5*time.Second {
					t.Error("missing controller timeout")
				}
				return &C.TailscaleExitNodes{State: "Ready", BackendState: "Running", ExitNodes: []C.TailscaleExitNode{{ID: id, ExitNodeOption: true}}}, nil
			},
		}
	}
	name := "tail net 中文"
	a, b := newOutbound(name, "account-a"), newOutbound("other", "account-b")
	tunnel.UpdateProxies(map[string]C.Proxy{
		name:          adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(a)),
		"other":       adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(&outbound.SingMux{ProxyAdapter: b})),
		"direct":      adapter.NewProxy(outbound.NewDirect()),
		"group":       adapter.NewProxy(outbound.NewBase(outbound.BaseOption{Name: "group", Type: C.Selector})),
		"unsupported": adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(outbound.NewBase(outbound.BaseOption{Name: "unsupported", Type: C.Tailscale}))),
	}, oldProviders)
	handler := router(false, "controller-secret", "", Cors{})
	request := func(path, authorization string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/proxies/"+path+"/tailscale/exit-nodes", nil)
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	for _, token := range []string{"", "Bearer wrong-secret"} {
		if got := request(url.PathEscape(name), token); got.Code != http.StatusUnauthorized {
			t.Fatalf("authentication status = %d", got.Code)
		}
	}
	if calls != 0 {
		t.Fatal("unauthorized request reached outbound")
	}
	for _, tc := range []struct {
		name string
		code int
		id   string
	}{
		{url.PathEscape(name), http.StatusOK, "account-a"},
		{"other", http.StatusOK, "account-b"},
		{"missing", http.StatusNotFound, ""},
		{"direct", http.StatusBadRequest, ""},
		{"group", http.StatusBadRequest, ""},
		{"unsupported", http.StatusBadRequest, ""},
	} {
		got := request(tc.name, "Bearer controller-secret")
		if got.Code != tc.code {
			t.Fatalf("%s: status %d, body %s", tc.name, got.Code, got.Body)
		}
		if tc.id != "" {
			var body C.TailscaleExitNodes
			if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.State != "Ready" || len(body.ExitNodes) != 1 || body.ExitNodes[0].ID != tc.id {
				t.Fatalf("wrong instance: %+v", body)
			}
		}
	}
	for _, tc := range []struct {
		err  error
		code int
	}{
		{errors.New("auth-key=secret; private state path"), http.StatusBadGateway},
		{context.DeadlineExceeded, http.StatusGatewayTimeout},
	} {
		a.query = func(context.Context) (*C.TailscaleExitNodes, error) { return nil, tc.err }
		got := request(url.PathEscape(name), "Bearer controller-secret")
		if got.Code != tc.code || strings.Contains(got.Body.String(), "auth-key") || strings.Contains(got.Body.String(), "private state") {
			t.Fatalf("error response = %d %s", got.Code, got.Body)
		}
	}
	a.query = func(context.Context) (*C.TailscaleExitNodes, error) {
		return &C.TailscaleExitNodes{State: "NotStarted", ExitNodes: []C.TailscaleExitNode{}}, nil
	}
	got := request(url.PathEscape(name), "Bearer controller-secret")
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"exitNodes":[]`) {
		t.Fatalf("empty response = %d %s", got.Code, got.Body)
	}
}
