package route

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
	MD "github.com/metacubex/mihomo/dns"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	D "github.com/miekg/dns"
)

type offlinePolicyResolver struct{ *MD.Resolver }

func (*offlinePolicyResolver) ExchangeContext(context.Context, *D.Msg) (*D.Msg, error) {
	panic("policy diagnostics must not exchange DNS messages")
}

func TestDNSPolicyMatchRoute(t *testing.T) {
	previous := resolver.DefaultResolver
	t.Cleanup(func() { resolver.DefaultResolver = previous })
	resolver.DefaultResolver = &offlinePolicyResolver{MD.NewResolver(MD.Config{
		Main:     []MD.NameServer{{Net: "rcode", Addr: "success", Source: "main"}},
		Fallback: []MD.NameServer{{Net: "rcode", Addr: "success", Source: "fallback"}},
		Policy:   []MD.Policy{{Key: "example.com,other.test", Domain: "example.com", NameServers: []MD.NameServer{{Net: "rcode", Addr: "success", Source: "policy"}}}},
	}).Resolver}
	router := dnsRouter()
	cases := []struct {
		query  string
		status int
		source string
		qtype  string
	}{
		{"domain=example.com", http.StatusOK, "policy", "A"},
		{"domain=EXAMPLE.COM.&type=aaaa", http.StatusOK, "policy", "AAAA"},
		{"domain=unknown.test", http.StatusOK, "main-or-fallback", "A"},
		{"domain=unknown.test&type=TXT", http.StatusOK, "main", "TXT"},
		{"domain=unknown.test&type=CNAME", http.StatusOK, "main-or-fallback", "CNAME"},
		{"", http.StatusBadRequest, "", ""},
		{"domain=.", http.StatusBadRequest, "", ""},
		{"domain=a..test", http.StatusBadRequest, "", ""},
		{"domain=" + url.QueryEscape("https://example.com"), http.StatusBadRequest, "", ""},
		{"domain=" + url.QueryEscape("white space.test"), http.StatusBadRequest, "", ""},
		{"domain=" + url.QueryEscape("*.example.com"), http.StatusBadRequest, "", ""},
		{"domain=example.com&type=invalid", http.StatusBadRequest, "", ""},
		{"domain=example.com&type=%ZZ", http.StatusBadRequest, "", ""},
		{"domain=example.com&type=AAAA;bad", http.StatusBadRequest, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, "/policy/match?"+tc.query, nil)
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != tc.status {
				t.Fatalf("status=%d, want %d: %s", recorder.Code, tc.status, recorder.Body.String())
			}
			if tc.status != http.StatusOK {
				var body HTTPError
				if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || body.Message == "" {
					t.Fatalf("missing error message: %s (%v)", recorder.Body.String(), err)
				}
				return
			}
			var match MD.PolicyMatch
			if err := json.Unmarshal(recorder.Body.Bytes(), &match); err != nil {
				t.Fatal(err)
			}
			if match.Source != tc.source || match.Type != tc.qtype || len(match.Upstreams) != 1 ||
				match.Conditional != (tc.source == "main-or-fallback") {
				t.Fatalf("unexpected match: %+v", match)
			}
			if tc.source == "policy" && match.Policy != "example.com,other.test" {
				t.Fatalf("original policy key not exposed: %+v", match)
			}
		})
	}
}

func TestDNSPolicyMatchDisabled(t *testing.T) {
	previous := resolver.DefaultResolver
	t.Cleanup(func() { resolver.DefaultResolver = previous })
	resolver.DefaultResolver = nil
	request, err := http.NewRequest(http.MethodGet, "/policy/match?domain=example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	dnsRouter().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("disabled DNS returned status=%d body=%s", recorder.Code, recorder.Body)
	}
}
