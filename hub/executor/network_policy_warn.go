package executor

import (
	"net"
	"strings"

	"github.com/metacubex/mihomo/component/networkpolicy"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// warnNetworkPolicyExternalController emits a WARN log when the
// external-controller endpoint is exposed in a way that lets anyone on
// the network manipulate proxy selection via PUT /network/context (and
// therefore override the user's manual choices via the network-policy
// state machine).
//
// Conditions for the warning (architecture §5.2.1):
//   - network-policy is configured (at least one select group has a
//     non-empty GroupPolicy)
//   - external-controller is enabled AND not bound to loopback
//   - no Secret is set
//   - AND the endpoint is not protected by strong mutual-TLS
//     (external-controller-tls with client-auth-cert AND ClientAuthType
//     == "require-and-verify" exempts the warning; weaker auth modes
//     like "request" / "verify-if-given" / empty do not)
//
// Scope: only the TCP and TLS endpoints are considered. Unix-socket
// (`external-controller-unix`) and named-pipe
// (`external-controller-pipe`) bindings rely on filesystem-level
// permissions (POSIX modes / Windows ACLs) for access control and are
// outside the scope of this warning per architecture §5.2.1.
//
// The warning is informational — the network-policy feature still
// works; mihomo does not block or reconfigure anything. Users who
// understand the implication (e.g., LAN-only deployments behind a
// trusted firewall) can ignore it.
func warnNetworkPolicyExternalController(cfg *config.Config) {
	if cfg == nil || cfg.Controller == nil {
		return
	}
	if !hasAnyNetworkPolicyGroup(cfg.Proxies) {
		return
	}

	ctrl := cfg.Controller
	plainExposed := isNonLoopbackBind(ctrl.ExternalController)
	tlsExposed := isNonLoopbackBind(ctrl.ExternalControllerTLS)

	if !plainExposed && !tlsExposed {
		return
	}

	// A non-empty secret guards both plain and TLS endpoints.
	if ctrl.Secret != "" {
		return
	}

	// TLS endpoint with strong mutual-TLS (cert + require-and-verify)
	// is considered protected; in that case the warning only applies
	// if the plain endpoint is also exposed.
	if tlsExposed && !plainExposed && cfg.TLS != nil && hasStrongClientAuth(cfg.TLS) {
		return
	}

	log.Warnln("[NetworkPolicy] external-controller is bound to a non-loopback address without a secret while network-policy is configured; any client that can reach the controller can manipulate proxy selection. Set `secret:` (or bind to loopback, or configure external-controller-tls with `tls.client-auth-type: require-and-verify` + `tls.client-auth-cert`) to restrict access.")
}

// isNonLoopbackBind reports whether the external-controller bind string
// resolves to a non-loopback host. Empty / unparseable values return
// false (endpoint effectively not exposed as far as this check is
// concerned). A bare ":9090" binds to all interfaces → non-loopback.
//
// Hostname handling is intentionally a static allowlist of well-known
// loopback aliases ("localhost", "ip6-localhost", "ip6-loopback")
// rather than a DNS lookup: doing net.LookupHost at startup would block
// on a flaky resolver, and the warning is informational anyway.
// Custom /etc/hosts aliases that map to loopback may produce a false-
// positive warning; the user can either use the canonical name or
// ignore the warning.
func isNonLoopbackBind(addr string) bool {
	if addr == "" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No host:port separator; treat as unparseable → conservative
		// false (don't warn on a malformed spec; the controller will
		// fail to bind anyway and produce its own error).
		return false
	}
	if host == "" {
		// e.g. ":9090" — binds to all interfaces.
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Static allowlist of well-known loopback hostname aliases.
		// Anything else → conservatively assume the operator meant
		// "exposed" and emit the warning.
		switch strings.ToLower(host) {
		case "localhost", "ip6-localhost", "ip6-loopback":
			return false
		}
		return true
	}
	return !ip.IsLoopback()
}

// hasStrongClientAuth reports whether the TLS config enforces
// certificate-based mutual authentication strong enough to exempt the
// warning. Requires both a client-auth certificate and the strictest
// auth type Go's crypto/tls accepts — any weaker mode (request,
// verify-if-given, require-any) doesn't actually reject unauthorized
// clients.
func hasStrongClientAuth(tls *config.TLS) bool {
	if tls == nil || tls.ClientAuthCert == "" {
		return false
	}
	return strings.EqualFold(tls.ClientAuthType, "require-and-verify")
}

// hasAnyNetworkPolicyGroup returns true if any proxy group carries a
// non-empty network-policy subfield, i.e., the network-policy feature
// is in use for this configuration.
func hasAnyNetworkPolicyGroup(proxies map[string]C.Proxy) bool {
	for _, p := range proxies {
		if np, ok := p.Adapter().(networkpolicy.SelectorWithPolicy); ok {
			if !np.NetworkPolicy().IsEmpty() {
				return true
			}
		}
	}
	return false
}
