package route

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/networkpolicy"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

// mockSelector is a SelectorWithPolicy implementation wide enough to
// drive the Manager + REST handlers. Kept in this package so test
// fixtures don't need to reach into the networkpolicy package's
// unexported mockSelector.
type mockSelector struct {
	name       string
	selected   string
	candidates map[string]struct{}
	policy     networkpolicy.GroupPolicy
	source     networkpolicy.GroupSource
}

func newMockSel(name, initial string, candidates []string, policy networkpolicy.GroupPolicy) *mockSelector {
	m := &mockSelector{
		name:       name,
		selected:   initial,
		candidates: make(map[string]struct{}, len(candidates)),
		policy:     policy,
		source: networkpolicy.GroupSource{
			StaticProxies: append([]string(nil), candidates...),
		},
	}
	for _, c := range candidates {
		m.candidates[c] = struct{}{}
	}
	return m
}

func (m *mockSelector) Name() string { return m.name }
func (m *mockSelector) Set(name string) error {
	if _, ok := m.candidates[name]; !ok {
		return &selectorErr{msg: "not in candidates: " + name}
	}
	m.selected = name
	return nil
}
func (m *mockSelector) Now() string                             { return m.selected }
func (m *mockSelector) HasProxy(n string) bool                  { _, ok := m.candidates[n]; return ok }
func (m *mockSelector) NetworkPolicy() networkpolicy.GroupPolicy { return m.policy }
func (m *mockSelector) GroupSource() networkpolicy.GroupSource   { return m.source }

type selectorErr struct{ msg string }

func (e *selectorErr) Error() string { return e.msg }

// setupManager installs a Manager with one select group governed by a
// single `office → us` network-policy mapping. Returns a cleanup fn.
func setupManager(t *testing.T) func() {
	t.Helper()
	networkpolicy.Uninstall()

	sel := newMockSel("auto", "hk", []string{"hk", "us", "DIRECT"}, networkpolicy.GroupPolicy{
		Mapping:      map[string]string{"office": "us"},
		HasDefault:   true,
		DefaultProxy: "DIRECT",
	})
	matcher, err := networkpolicy.ParseMatch(map[string]any{"ssid": "office-5g"})
	if err != nil {
		t.Fatalf("parse matcher: %v", err)
	}
	nets := []networkpolicy.Network{{Name: "office", Matcher: matcher}}
	networkpolicy.Install(nets, []networkpolicy.SelectorWithPolicy{sel}, nil)

	return func() { networkpolicy.Uninstall() }
}

// serve executes a request against the /network/context router and
// returns the recorded response.
func serve(method, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/", strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	// Chi router carries the route path; mount at root since we test
	// a single subrouter in isolation.
	r := chi.NewRouter()
	r.Mount("/", networkContextRouter())
	r.ServeHTTP(w, req)
	return w
}

// --- PUT /network/context ----------------------------------------------

func TestPutNetworkContext_Happy(t *testing.T) {
	defer setupManager(t)()

	body := `{"version":1,"interfaces":[{"name":"wlan0","iface_type":"wifi","ssid":"office-5g"}]}`
	w := serve(http.MethodPut, body)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		MatchedNetwork *string `json:"matched_network"`
		Applied        []struct {
			Group           string  `json:"group"`
			TargetProxy     *string `json:"target_proxy"`
			AppliedProxy    string  `json:"applied_proxy"`
			Changed         bool    `json:"changed"`
			SelectionSource string  `json:"selection_source"`
			Reason          string  `json:"reason"`
		} `json:"applied"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, w.Body.String())
	}
	if resp.MatchedNetwork == nil || *resp.MatchedNetwork != "office" {
		t.Errorf("want matched_network=office, got %+v", resp.MatchedNetwork)
	}
	if len(resp.Applied) != 1 {
		t.Fatalf("want 1 applied row, got %d", len(resp.Applied))
	}
	if resp.Applied[0].Reason != networkpolicy.ReasonMatched {
		t.Errorf("want matched, got %q", resp.Applied[0].Reason)
	}
	if resp.Applied[0].AppliedProxy != "us" {
		t.Errorf("want applied=us, got %q", resp.Applied[0].AppliedProxy)
	}
}

func TestPutNetworkContext_MalformedBody(t *testing.T) {
	defer setupManager(t)()

	w := serve(http.MethodPut, `not json`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
	code := decodeErrCode(t, w.Body.Bytes())
	if code != "malformed_body" {
		t.Errorf("want code=malformed_body, got %q", code)
	}
}

// Strict JSON contract: trailing non-whitespace after the root value
// is malformed_body. Bare json.Decoder.Decode would silently accept
// "{...}garbage" — the strict-end check in the handler rejects it.
func TestPutNetworkContext_TrailingJunkRejected(t *testing.T) {
	defer setupManager(t)()

	w := serve(http.MethodPut, `{"version":1,"interfaces":[]}garbage`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("trailing junk must be 400; got %d body=%s", w.Code, w.Body.String())
	}
	if got := decodeErrCode(t, w.Body.Bytes()); got != "malformed_body" {
		t.Errorf("want malformed_body for trailing junk, got %q", got)
	}
}

// Body-size cap: pathological bodies above maxPutBodyBytes are rejected
// as malformed_body via http.MaxBytesReader. The 10 MiB cap is generous
// enough that no realistic body hits it, but it bounds DoS exposure
// from local hostile processes / authenticated-but-misbehaving clients
// that the secret + loopback warning don't cover.
func TestPutNetworkContext_OversizeBodyRejected(t *testing.T) {
	defer setupManager(t)()

	// Build a body larger than maxPutBodyBytes. Use a JSON-valid string
	// padded with a long dns_suffix entry so the cap is what fails,
	// not the parser hitting EOF mid-token.
	var buf bytes.Buffer
	buf.WriteString(`{"version":1,"interfaces":[],"dns_suffix":["`)
	const targetSize = 12 << 20 // 12 MiB > 10 MiB cap
	for buf.Len() < targetSize {
		buf.WriteString("padpadpadpadpadpadpadpadpadpadpadpadpadpadpadpad")
	}
	buf.WriteString(`"]}`)

	w := serve(http.MethodPut, buf.String())
	if w.Code != http.StatusBadRequest {
		t.Errorf("oversize body must be 400; got %d", w.Code)
	}
	if got := decodeErrCode(t, w.Body.Bytes()); got != "malformed_body" {
		t.Errorf("want malformed_body for oversize, got %q", got)
	}
}

func TestPutNetworkContext_MissingVersion(t *testing.T) {
	defer setupManager(t)()

	// UnmarshalJSON enforces version presence → malformed_body.
	w := serve(http.MethodPut, `{"interfaces":[]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
	if got := decodeErrCode(t, w.Body.Bytes()); got != "malformed_body" {
		t.Errorf("want malformed_body, got %q", got)
	}
}

func TestPutNetworkContext_InvalidVersion(t *testing.T) {
	defer setupManager(t)()

	w := serve(http.MethodPut, `{"version":2,"interfaces":[]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
	if got := decodeErrCode(t, w.Body.Bytes()); got != "invalid_version" {
		t.Errorf("want invalid_version, got %q", got)
	}
}

func TestPutNetworkContext_InvalidTTL(t *testing.T) {
	defer setupManager(t)()

	w := serve(http.MethodPut, `{"version":1,"interfaces":[],"ttl":0}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d; body=%s", w.Code, w.Body.String())
	}
	if got := decodeErrCode(t, w.Body.Bytes()); got != "invalid_ttl" {
		t.Errorf("want invalid_ttl, got %q", got)
	}
}

func TestPutNetworkContext_InvalidTTL_AboveUpperBound(t *testing.T) {
	defer setupManager(t)()

	// maxTTLSeconds is an unexported package constant; 10 years + 1 second
	// hard-coded here mirrors component/networkpolicy/context.go and pins
	// the REST layer's end-to-end upper-bound rejection to invalid_ttl
	// (rather than internal_error / invalid_field).
	const aboveMaxTTL = 10*365*86400 + 1
	body := fmt.Sprintf(`{"version":1,"interfaces":[],"ttl":%d}`, aboveMaxTTL)
	w := serve(http.MethodPut, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d; body=%s", w.Code, w.Body.String())
	}
	if got := decodeErrCode(t, w.Body.Bytes()); got != "invalid_ttl" {
		t.Errorf("want invalid_ttl, got %q", got)
	}
}

func TestPutNetworkContext_TooManyInterfaces(t *testing.T) {
	defer setupManager(t)()

	var buf bytes.Buffer
	buf.WriteString(`{"version":1,"interfaces":[`)
	for i := 0; i < networkpolicy.MaxInterfaces+1; i++ {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(`{"name":"eth`)
		buf.WriteString(strconv.Itoa(i))
		buf.WriteString(`"}`)
	}
	buf.WriteString(`]}`)

	w := serve(http.MethodPut, buf.String())
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d; body=%s", w.Code, w.Body.String())
	}
	if got := decodeErrCode(t, w.Body.Bytes()); got != "too_many_interfaces" {
		t.Errorf("want too_many_interfaces, got %q", got)
	}
}

func TestPutNetworkContext_DuplicateIfaceName(t *testing.T) {
	defer setupManager(t)()

	w := serve(http.MethodPut, `{"version":1,"interfaces":[{"name":"en0"},{"name":"en0"}]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d; body=%s", w.Code, w.Body.String())
	}
	if got := decodeErrCode(t, w.Body.Bytes()); got != "duplicate_iface_name" {
		t.Errorf("want duplicate_iface_name, got %q", got)
	}
}

func TestPutNetworkContext_InvalidGatewayCombo(t *testing.T) {
	defer setupManager(t)()

	w := serve(http.MethodPut, `{"version":1,"interfaces":[{"name":"en0","gateway_mac":"aa:bb:cc:dd:ee:ff"}]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d; body=%s", w.Code, w.Body.String())
	}
	if got := decodeErrCode(t, w.Body.Bytes()); got != "invalid_gateway_combo" {
		t.Errorf("want invalid_gateway_combo, got %q", got)
	}
}

func TestPutNetworkContext_InvalidField_BadMAC(t *testing.T) {
	defer setupManager(t)()

	w := serve(http.MethodPut, `{"version":1,"interfaces":[{"name":"en0","gateway_ip":"1.2.3.4","gateway_mac":"not-a-mac"}]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d; body=%s", w.Code, w.Body.String())
	}
	if got := decodeErrCode(t, w.Body.Bytes()); got != "invalid_field" {
		t.Errorf("want invalid_field (bad MAC), got %q", got)
	}
}

// Composite: gateway_mac is invalid AND gateway_ip is empty. With the
// sentinel-based classifier, normalize() emits ErrInvalidField for the
// MAC parse failure FIRST (before validate() reaches the gateway_combo
// check), so the REST code must be invalid_field — not the misleading
// invalid_gateway_combo a struct-only classifier would have produced.
func TestPutNetworkContext_BadMAC_EmptyGatewayIP_RoutesToInvalidField(t *testing.T) {
	defer setupManager(t)()

	w := serve(http.MethodPut, `{"version":1,"interfaces":[{"name":"en0","gateway_mac":"not-a-mac"}]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d; body=%s", w.Code, w.Body.String())
	}
	if got := decodeErrCode(t, w.Body.Bytes()); got != "invalid_field" {
		t.Errorf("composite (bad MAC + empty IP) should route to invalid_field, got %q", got)
	}
}

// Composite: version=2 AND too many interfaces. The classifier must
// route on the FIRST emitted error per NormalizeAndValidate's order
// (too_many_interfaces is checked before version).
func TestPutNetworkContext_BadVersion_TooManyInterfaces_RoutesToTooMany(t *testing.T) {
	defer setupManager(t)()

	var buf bytes.Buffer
	buf.WriteString(`{"version":2,"interfaces":[`)
	for i := 0; i < networkpolicy.MaxInterfaces+1; i++ {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(`{"name":"eth`)
		buf.WriteString(strconv.Itoa(i))
		buf.WriteString(`"}`)
	}
	buf.WriteString(`]}`)

	w := serve(http.MethodPut, buf.String())
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d; body=%s", w.Code, w.Body.String())
	}
	if got := decodeErrCode(t, w.Body.Bytes()); got != "too_many_interfaces" {
		t.Errorf("composite (bad version + too many) should route to too_many_interfaces (emitted first); got %q", got)
	}
}

func TestPutNetworkContext_InvalidField_BadIfaceType(t *testing.T) {
	defer setupManager(t)()

	w := serve(http.MethodPut, `{"version":1,"interfaces":[{"name":"en0","iface_type":"satellite"}]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d; body=%s", w.Code, w.Body.String())
	}
	if got := decodeErrCode(t, w.Body.Bytes()); got != "invalid_field" {
		t.Errorf("want invalid_field (bad iface_type), got %q", got)
	}
}

// Regression: schema-legal large body must not be rejected by an
// arbitrary REST-layer size cap. Architecture §5.4.5 leaves
// dns_suffix / subnets element counts unbounded; any cap above the
// manager's actual memory limits is contract-violating.
func TestPutNetworkContext_LargeBody_NotRejected(t *testing.T) {
	defer setupManager(t)()

	var buf bytes.Buffer
	buf.WriteString(`{"version":1,"interfaces":[],"dns_suffix":[`)
	const n = 80000 // ~1.5 MiB after JSON-encoding
	for i := 0; i < n; i++ {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteByte('"')
		buf.WriteString("entry")
		buf.WriteString(strconv.Itoa(i))
		buf.WriteString(".example.com")
		buf.WriteByte('"')
	}
	buf.WriteString(`]}`)

	w := serve(http.MethodPut, buf.String())
	if w.Code != http.StatusOK {
		// Truncate body in error message to avoid a multi-MB dump.
		bodyPreview := w.Body.String()
		if len(bodyPreview) > 200 {
			bodyPreview = bodyPreview[:200]
		}
		t.Errorf("schema-legal large body must be accepted; got %d body=%s", w.Code, bodyPreview)
	}
}

// invalid_field message must follow §5.4.8's "field: <path>, reason:
// <why>" format so host log parsers can extract the field path.
func TestPutNetworkContext_InvalidField_MessageFormat(t *testing.T) {
	defer setupManager(t)()

	w := serve(http.MethodPut, `{"version":1,"interfaces":[{"name":"en0","iface_type":"satellite"}]}`)
	var resp struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(resp.Message, "field: interfaces[0].iface_type, reason:") {
		t.Errorf("want 'field: <path>, reason: <why>' format, got %q", resp.Message)
	}
}

func TestPutNetworkContext_WireEncodingMatchedNone(t *testing.T) {
	defer setupManager(t)()

	// SSID doesn't match any network → MatchedNone → wire JSON null.
	body := `{"version":1,"interfaces":[{"name":"wlan0","iface_type":"wifi","ssid":"random-wifi"}]}`
	w := serve(http.MethodPut, body)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"matched_network":null`) {
		t.Errorf("MatchedNone must serialize matched_network as JSON null; got %s", w.Body.String())
	}
	// The default branch should kick in → AppliedProxy=DIRECT.
	if !strings.Contains(w.Body.String(), `"applied_proxy":"DIRECT"`) {
		t.Errorf("want default branch to apply DIRECT; got %s", w.Body.String())
	}
}

func TestPutNetworkContext_NoManager(t *testing.T) {
	networkpolicy.Uninstall()
	w := serve(http.MethodPut, `{"version":1,"interfaces":[]}`)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("want 503 when no manager, got %d", w.Code)
	}
	if got := decodeErrCode(t, w.Body.Bytes()); got != "internal_error" {
		t.Errorf("want internal_error, got %q", got)
	}
}

// --- DELETE /network/context -------------------------------------------

func TestDeleteNetworkContext_NoManager(t *testing.T) {
	networkpolicy.Uninstall()
	w := serve(http.MethodDelete, "")
	if w.Code != http.StatusNoContent {
		t.Errorf("DELETE must return 204 even without manager (idempotent per §5.4.3); got %d", w.Code)
	}
}

func TestDeleteNetworkContext_PreservesState(t *testing.T) {
	defer setupManager(t)()

	// Establish state via PUT.
	serve(http.MethodPut, `{"version":1,"interfaces":[{"name":"wlan0","iface_type":"wifi","ssid":"office-5g"}]}`)

	// DELETE → 204.
	w := serve(http.MethodDelete, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", w.Code)
	}

	// GET should now report no context but keep the group row with its
	// (preserved) source / current_proxy. §5.4.3 contract: DELETE clears
	// the ctx snapshot only; per-group state machine is untouched.
	w = serve(http.MethodGet, "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET want 200, got %d", w.Code)
	}
	var st struct {
		Context *any `json:"context"`
		Groups  []struct {
			Group           string `json:"group"`
			CurrentProxy    string `json:"current_proxy"`
			SelectionSource string `json:"selection_source"`
		} `json:"groups"`
	}
	json.Unmarshal(w.Body.Bytes(), &st)
	if st.Context != nil && *st.Context != nil {
		t.Errorf("DELETE should have nil'd context; got %+v", st.Context)
	}
	if len(st.Groups) != 1 {
		t.Fatalf("DELETE must preserve groups[]; got %d rows", len(st.Groups))
	}
	if st.Groups[0].Group != "auto" {
		t.Errorf("preserved group row should be 'auto', got %q", st.Groups[0].Group)
	}
	if st.Groups[0].CurrentProxy != "us" {
		t.Errorf("DELETE must preserve current_proxy=us (state machine untouched); got %q", st.Groups[0].CurrentProxy)
	}
	if st.Groups[0].SelectionSource == "" {
		t.Errorf("DELETE must preserve selection_source; got empty")
	}
}

// --- GET /network/context ----------------------------------------------

func TestGetNetworkContext_NoManager(t *testing.T) {
	networkpolicy.Uninstall()
	w := serve(http.MethodGet, "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET must return 200 with null body even without manager; got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"context":null`) {
		t.Errorf("want context:null, got %s", body)
	}
}

func TestGetNetworkContext_HappyAfterPut(t *testing.T) {
	defer setupManager(t)()
	serve(http.MethodPut, `{"version":1,"interfaces":[{"name":"wlan0","iface_type":"wifi","ssid":"office-5g"}]}`)

	w := serve(http.MethodGet, "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var st struct {
		MatchedNetwork *string `json:"matched_network"`
		Groups         []struct {
			Group              string  `json:"group"`
			CurrentProxy       string  `json:"current_proxy"`
			SelectionSource    string  `json:"selection_source"`
			LastMatchedNetwork *string `json:"last_matched_network"`
		} `json:"groups"`
		AgeSeconds *int64 `json:"age_seconds"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if st.MatchedNetwork == nil || *st.MatchedNetwork != "office" {
		t.Errorf("want matched=office, got %+v", st.MatchedNetwork)
	}
	if len(st.Groups) != 1 || st.Groups[0].CurrentProxy != "us" {
		t.Errorf("want groups[0].current_proxy=us, got %+v", st.Groups)
	}
	if st.AgeSeconds == nil {
		t.Errorf("want age_seconds populated")
	}
}

// --- helpers -----------------------------------------------------------

func decodeErrCode(t *testing.T, body []byte) string {
	t.Helper()
	var resp struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode error response: %v; body=%s", err, body)
	}
	return resp.Code
}

