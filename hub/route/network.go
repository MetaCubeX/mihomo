package route

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/metacubex/mihomo/component/networkpolicy"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// maxPutBodyBytes caps the PUT /network/context body to 10 MiB. The
// architecture (§5.4.5) intentionally leaves dns_suffix / subnets
// element counts unbounded, so any cap is implementation pragma rather
// than a wire contract. 10 MiB is generous enough to cover any
// plausible legitimate body (32 ifaces × thousands of subnets ≪ 10 MiB
// even with verbose JSON formatting) while bounding the linear
// allocate / sort / dedupe cost of a pathological multi-GB request.
//
// Defense-in-depth scope: this cap also protects against loopback-
// local hostile processes and authenticated-but-misbehaving clients,
// which the external-controller secret + non-loopback warning don't
// cover.
const maxPutBodyBytes = 10 << 20

// networkContextRouter mounts PUT / DELETE / GET at /network/context per
// architecture §5.4.
func networkContextRouter() http.Handler {
	r := chi.NewRouter()
	r.Put("/", putNetworkContext)
	r.Delete("/", deleteNetworkContext)
	r.Get("/", getNetworkContext)
	return r
}

// npErrorResponse is the standard error payload (architecture §5.4.8 /
// §2.5). Short code + human-readable message; host uses code for
// structured error handling.
type npErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeNPError(w http.ResponseWriter, r *http.Request, httpStatus int, code, msg string) {
	render.Status(r, httpStatus)
	render.JSON(w, r, npErrorResponse{Code: code, Message: msg})
}

// putNetworkContext handles PUT /network/context per architecture §5.4.1.
// Decodes the body, classifies validation errors into the error-code
// vocabulary §5.4.8 requires, calls manager.PutContext, and serializes
// the applied[] response with the wire encoding rules from §5.6.4
// (internal <none> / nil both → JSON null for matched_network).
func putNetworkContext(w http.ResponseWriter, r *http.Request) {
	mgr := networkpolicy.Global()
	if mgr == nil {
		writeNPError(w, r, http.StatusServiceUnavailable, "internal_error", "network-policy manager not yet initialized")
		return
	}

	// Body decoding contract:
	//   - http.MaxBytesReader caps the body at maxPutBodyBytes; any
	//     overflow produces a MaxBytesError that surfaces through the
	//     decoder's first Decode call as malformed_body (with a clear
	//     "request body too large" message).
	//   - Strict JSON: no trailing content after the root object;
	//     "{...}garbage" is malformed_body, not silently truncated as
	//     bare json.Decoder.Decode would allow.
	//
	// Implementation: a follow-up Decode of a sink that doesn't return
	// io.EOF proves there's a second top-level token (i.e. trailing
	// junk). This is the standard library's idiom for strict JSON
	// streams.
	r.Body = http.MaxBytesReader(w, r.Body, maxPutBodyBytes)

	var ctx networkpolicy.NetworkContext
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&ctx); err != nil {
		code := "malformed_body"
		msg := stripSentinelPrefix(err)
		writeNPError(w, r, http.StatusBadRequest, code, msg)
		return
	}
	var sink json.RawMessage
	if err := dec.Decode(&sink); err != io.EOF {
		writeNPError(w, r, http.StatusBadRequest, "malformed_body", "trailing content after JSON root")
		return
	}

	result, err := mgr.PutContext(&ctx)
	if err != nil {
		code, msg := classifyPutError(err)
		// Only known validation sentinels map to 400. Anything else
		// (including future internal errors from Manager.PutContext)
		// surfaces as 5xx internal_error so host doesn't mistake a
		// transient kernel failure for a permanent config bug and
		// suppress retries (architecture §5.4.8 host handling rule).
		if code == "internal_error" {
			writeNPError(w, r, http.StatusInternalServerError, code, msg)
			return
		}
		writeNPError(w, r, http.StatusBadRequest, code, msg)
		return
	}

	render.JSON(w, r, putResultToWire(result))
}

// deleteNetworkContext handles DELETE /network/context per §5.4.3.
// Always returns 204 (even when no ctx was cached). Preserves the
// per-group state machine; the TTL timer is cancelled; the state
// machine rolls forward only on the next PUT per §5.6.2.
func deleteNetworkContext(w http.ResponseWriter, r *http.Request) {
	mgr := networkpolicy.Global()
	if mgr != nil {
		mgr.DeleteContext()
	}
	render.NoContent(w, r)
}

// getNetworkContext handles GET /network/context per §5.4.4.
//
// No-context case returns 200 with context / matched_network / expires_at
// / age_seconds all set to JSON null and groups[] still populated so
// polling clients don't have to branch on 200-vs-404.
func getNetworkContext(w http.ResponseWriter, r *http.Request) {
	mgr := networkpolicy.Global()
	if mgr == nil {
		// Renders the same shape as "no context" so host polling stays
		// uniform before and after Install completes.
		render.JSON(w, r, noContextStatus(nil))
		return
	}
	status := mgr.GetStatus()
	render.JSON(w, r, statusToWire(status))
}

// classifyPutError maps a NetworkContext validation error to the §2.5
// error-code vocabulary via the sentinel chain the networkpolicy
// package wraps into each error. errors.Is preserves ordering — the
// first sentinel NormalizeAndValidate actually emitted is the one we
// route on, so composite-failure bodies always see the correct
// (code, message) pair.
//
// The returned message is the error's full String() form, which for
// invalid_field errors matches the §5.4.8 "field: <path>, reason:
// <why>" contract because the networkpolicy package emits them that
// way at their source sites.
//
// Unknown errors (no recognized sentinel) map to internal_error rather
// than invalid_field. This matters for forward-compat: if a future
// Manager.PutContext returns a transient internal error, the REST
// layer surfaces 5xx so host's retry policy kicks in (architecture
// §5.4.8 "5xx → 按现有 retry 策略退避重试"); misclassifying as
// invalid_field would suppress retries and silently strand the host.
func classifyPutError(err error) (code, msg string) {
	if err == nil {
		return "", ""
	}
	msg = stripSentinelPrefix(err)
	switch {
	case errors.Is(err, networkpolicy.ErrMalformedBody):
		// Defense-in-depth: putNetworkContext catches ErrMalformedBody
		// at the DecodeJSON stage already, so this branch is unreachable
		// from the live PUT path. Kept so a future code path that flows
		// ErrMalformedBody through Manager.PutContext still routes
		// correctly.
		return "malformed_body", msg
	case errors.Is(err, networkpolicy.ErrInvalidVersion):
		return "invalid_version", msg
	case errors.Is(err, networkpolicy.ErrInvalidTTL):
		return "invalid_ttl", msg
	case errors.Is(err, networkpolicy.ErrTooManyInterfaces):
		return "too_many_interfaces", msg
	case errors.Is(err, networkpolicy.ErrDuplicateIfaceName):
		return "duplicate_iface_name", msg
	case errors.Is(err, networkpolicy.ErrInvalidGatewayCombo):
		return "invalid_gateway_combo", msg
	case errors.Is(err, networkpolicy.ErrInvalidField):
		return "invalid_field", msg
	}
	// Unrecognized error: surface as internal_error 5xx so host treats
	// it as transient and applies its retry/backoff policy. The full
	// error.Error() goes into the message for diagnostics.
	return "internal_error", err.Error()
}

// classifySentinels is the ordered list of sentinel errors recognized
// by classifyPutError + stripSentinelPrefix. Derived from the
// networkpolicy package's exported errors so adding a new sentinel
// there + a switch case in classifyPutError is sufficient — the prefix
// stripper picks it up automatically without a manual hardcoded
// duplicate list (which round-3 review flagged as a drift risk).
var classifySentinels = []error{
	networkpolicy.ErrMalformedBody,
	networkpolicy.ErrInvalidVersion,
	networkpolicy.ErrInvalidTTL,
	networkpolicy.ErrTooManyInterfaces,
	networkpolicy.ErrDuplicateIfaceName,
	networkpolicy.ErrInvalidGatewayCombo,
	networkpolicy.ErrInvalidField,
}

// stripSentinelPrefix removes the leading "<code>: " inserted by the
// fmt.Errorf("%w: ...", ErrXxx) wrap pattern so the outgoing REST
// message reads cleanly ("field: interfaces[0].bssid, reason: ...")
// rather than duplicating the code ("invalid_field: field: ..., reason:
// ..."). If no sentinel matches, return the full string so nothing is
// lost.
func stripSentinelPrefix(err error) string {
	msg := err.Error()
	for _, s := range classifySentinels {
		prefix := s.Error() + ": "
		if len(msg) >= len(prefix) && msg[:len(prefix)] == prefix {
			return msg[len(prefix):]
		}
	}
	return msg
}

// Wire types (package-level so PUT / GET / no-ctx code paths share a
// single source of truth — adding a field happens in one place rather
// than risking tag drift across three duplicates).

type appliedRowWire struct {
	Group           string  `json:"group"`
	TargetProxy     *string `json:"target_proxy"`
	AppliedProxy    string  `json:"applied_proxy"`
	Changed         bool    `json:"changed"`
	SelectionSource string  `json:"selection_source"`
	Reason          string  `json:"reason"`
}

type putWire struct {
	MatchedNetwork *string          `json:"matched_network"`
	Applied        []appliedRowWire `json:"applied"`
	ExpiresAt      *int64           `json:"expires_at"`
}

type statusGroupWire struct {
	Group              string  `json:"group"`
	CurrentProxy       string  `json:"current_proxy"`
	SelectionSource    string  `json:"selection_source"`
	LastMatchedNetwork *string `json:"last_matched_network"`
}

type statusWire struct {
	Context        any               `json:"context"`
	MatchedNetwork *string           `json:"matched_network"`
	Groups         []statusGroupWire `json:"groups"`
	ExpiresAt      *int64            `json:"expires_at"`
	AgeSeconds     *int64            `json:"age_seconds"`
}

// putResultToWire converts the internal PutResult to the JSON body
// per §5.4.2. matched_network uses the wire encoding from §5.6.4:
// both the MatchedNone sentinel and the nil (never-evaluated) state
// serialize to JSON null; host disambiguates via selection_source in
// applied[] entries.
func putResultToWire(r *networkpolicy.PutResult) any {
	out := putWire{
		MatchedNetwork: wireMatchedNetwork(r.MatchedNetworkPresent, r.MatchedNetwork),
		Applied:        make([]appliedRowWire, 0, len(r.Applied)),
	}
	for _, a := range r.Applied {
		row := appliedRowWire{
			Group:           a.Group,
			AppliedProxy:    a.AppliedProxy,
			Changed:         a.Changed,
			SelectionSource: a.SelectionSource,
			Reason:          a.Reason,
		}
		if a.TargetProxy != "" {
			target := a.TargetProxy
			row.TargetProxy = &target
		}
		out.Applied = append(out.Applied, row)
	}
	if r.ExpiresAt != nil {
		unix := r.ExpiresAt.Unix()
		out.ExpiresAt = &unix
	}
	return out
}

// statusToWire converts the internal StatusResult to the §5.4.4 JSON.
func statusToWire(s *networkpolicy.StatusResult) any {
	if s == nil || !s.HasContext {
		return noContextStatus(s)
	}
	out := statusWire{
		Context:        contextForStatusWire(s.Context),
		MatchedNetwork: wireMatchedNetwork(s.MatchedNetworkPresent, s.MatchedNetwork),
		Groups:         buildStatusGroups(s.Groups),
	}
	if s.ExpiresAt != nil {
		unix := s.ExpiresAt.Unix()
		out.ExpiresAt = &unix
	}
	if s.AgeSeconds != nil {
		age := *s.AgeSeconds
		out.AgeSeconds = &age
	}
	return out
}

// noContextStatus renders the GET body when no ctx is cached — matches
// §5.4.4's "context: null + matched_network: null + expires_at: null +
// age_seconds: null" shape so host clients don't need to branch.
// groups[] is still populated if the caller passed a StatusResult so
// current per-group source / selected stay visible.
func noContextStatus(s *networkpolicy.StatusResult) any {
	out := statusWire{Groups: []statusGroupWire{}}
	if s != nil {
		out.Groups = buildStatusGroups(s.Groups)
	}
	return out
}

// buildStatusGroups converts the internal []GroupStatus to the wire
// shape, applying the §5.6.4 last_matched_network null-encoding rule.
func buildStatusGroups(in []networkpolicy.GroupStatus) []statusGroupWire {
	out := make([]statusGroupWire, 0, len(in))
	for _, g := range in {
		out = append(out, statusGroupWire{
			Group:              g.Group,
			CurrentProxy:       g.CurrentProxy,
			SelectionSource:    g.SelectionSource,
			LastMatchedNetwork: wireMatchedNetwork(g.LastMatchedNetworkPresent, g.LastMatchedNetwork),
		})
	}
	return out
}

// wireMatchedNetwork maps the internal tri-state (present bool + value)
// to the wire representation per §5.6.4:
//   - present == false  →  JSON null (never evaluated)
//   - value == MatchedNone  →  JSON null (evaluated, no match)
//   - concrete name  →  JSON string
//
// Host disambiguates the two null cases via selection_source.
func wireMatchedNetwork(present bool, value string) *string {
	if !present || value == networkpolicy.MatchedNone {
		return nil
	}
	v := value
	return &v
}

// contextForStatusWire serializes the cached NetworkContext for the GET
// response in the same wire shape as PUT input, minus ttl (§5.4.4
// "不回显 ttl"). NetworkContext's default JSON marshaling already
// omits the unexported derived fields and honors the snake_case struct
// tags; we just need to suppress the TTL field by shallow-cloning and
// nil'ing it. The Interfaces slice is shared with the cached ctx but
// only for read — no mutation.
func contextForStatusWire(ctx *networkpolicy.NetworkContext) any {
	if ctx == nil {
		return nil
	}
	clone := *ctx
	clone.TTL = nil
	return &clone
}
