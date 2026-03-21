package httpmask

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"time"

	"github.com/metacubex/http"
)

const (
	tunnelAuthHeaderKey    = "Authorization"
	tunnelAuthHeaderPrefix = "Bearer "
	tunnelAuthQueryKey     = "auth"
)

type tunnelAuth struct {
	key  [32]byte // derived HMAC key
	skew time.Duration
}

func newTunnelAuth(key string, skew time.Duration) *tunnelAuth {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	if skew <= 0 {
		skew = 60 * time.Second
	}

	// Domain separation: keep this HMAC key independent from other uses of cfg.Key.
	h := sha256.New()
	_, _ = h.Write([]byte("sudoku-httpmask-auth-v1:"))
	_, _ = h.Write([]byte(key))

	var sum [32]byte
	h.Sum(sum[:0])

	return &tunnelAuth{key: sum, skew: skew}
}

func (a *tunnelAuth) token(mode TunnelMode, method, path string, now time.Time) string {
	if a == nil {
		return ""
	}

	ts := now.Unix()
	sig := a.sign(mode, method, path, ts)

	var buf [8 + 16]byte
	binary.BigEndian.PutUint64(buf[:8], uint64(ts))
	copy(buf[8:], sig[:])
	return base64.RawURLEncoding.EncodeToString(buf[:])
}

func (a *tunnelAuth) verify(headers map[string]string, mode TunnelMode, method, path string, now time.Time) bool {
	if a == nil {
		return true
	}
	if headers == nil {
		return false
	}
	return a.verifyValue(headers["authorization"], mode, method, path, now)
}

func (a *tunnelAuth) verifyValue(val string, mode TunnelMode, method, path string, now time.Time) bool {
	if a == nil {
		return true
	}

	val = strings.TrimSpace(val)
	if val == "" {
		return false
	}

	// Accept both "Bearer <token>" and raw token forms (for forward proxies / CDNs that may normalize headers).
	if len(val) > len(tunnelAuthHeaderPrefix) && strings.EqualFold(val[:len(tunnelAuthHeaderPrefix)], tunnelAuthHeaderPrefix) {
		val = strings.TrimSpace(val[len(tunnelAuthHeaderPrefix):])
	}
	if val == "" {
		return false
	}

	raw, err := base64.RawURLEncoding.DecodeString(val)
	if err != nil || len(raw) != 8+16 {
		return false
	}

	ts := int64(binary.BigEndian.Uint64(raw[:8]))
	nowTS := now.Unix()
	delta := nowTS - ts
	if delta < 0 {
		delta = -delta
	}
	if delta > int64(a.skew.Seconds()) {
		return false
	}

	want := a.sign(mode, method, path, ts)
	return subtle.ConstantTimeCompare(raw[8:], want[:]) == 1
}

func (a *tunnelAuth) sign(mode TunnelMode, method, path string, ts int64) [16]byte {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	path = strings.TrimSpace(path)

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(ts))

	mac := hmac.New(sha256.New, a.key[:])
	_, _ = mac.Write([]byte(mode))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(method))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(path))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(tsBuf[:])

	var full [32]byte
	mac.Sum(full[:0])

	var out [16]byte
	copy(out[:], full[:16])
	return out
}

type httpHeaderSetter = http.Header

func applyTunnelAuthHeader(h httpHeaderSetter, auth *tunnelAuth, mode TunnelMode, method, path string) {
	if auth == nil || h == nil {
		return
	}
	token := auth.token(mode, method, path, time.Now())
	if token == "" {
		return
	}
	h.Set(tunnelAuthHeaderKey, tunnelAuthHeaderPrefix+token)
}

func applyTunnelAuth(req *http.Request, auth *tunnelAuth, mode TunnelMode, method, path string) {
	if auth == nil || req == nil {
		return
	}
	token := auth.token(mode, method, path, time.Now())
	if token == "" {
		return
	}
	req.Header.Set(tunnelAuthHeaderKey, tunnelAuthHeaderPrefix+token)
	if req.URL != nil {
		q := req.URL.Query()
		q.Set(tunnelAuthQueryKey, token)
		req.URL.RawQuery = q.Encode()
	}
}
