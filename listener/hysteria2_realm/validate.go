package hysteria2_realm

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/common/httputils"
)

const (
	maxAddresses   = 8
	nonceHexLength = 32 // 16 bytes
	obfsHexLength  = 64 // 32 bytes
)

const (
	errBadRequest      = "bad_request"
	errInvalidToken    = "invalid_token"
	errRealmTaken      = "realm_taken"
	errRealmLimit      = "realm_limit_reached"
	errIPLimit         = "ip_limit_reached"
	errRealmNotFound   = "realm_not_found"
	errAttemptNotFound = "attempt_not_found"
	errRateLimited     = "rate_limited"
	errNotFound        = "not_found"
)

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request, header string) string {
	if ap := httputils.ClientAddrPortFromHeader(r, header); ap.IsValid() {
		return ap.Addr().String()
	}

	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return host
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}

func validateAddresses(addrs []string) error {
	if len(addrs) == 0 {
		return fmt.Errorf("at least one address required")
	}
	if len(addrs) > maxAddresses {
		return fmt.Errorf("too many addresses (max %d)", maxAddresses)
	}
	for _, a := range addrs {
		ap, err := netip.ParseAddrPort(a)
		if err != nil || !ap.IsValid() {
			return fmt.Errorf("invalid address: %s", a)
		}
	}
	return nil
}

func validateHexField(name, value string, length int) error {
	if len(value) != length {
		return fmt.Errorf("%s must be %d hex characters", name, length)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%s must be valid hex", name)
	}
	return nil
}
