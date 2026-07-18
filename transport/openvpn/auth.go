package openvpn

import (
	"errors"
	"strings"
)

const (
	AuthRetryNone       = "none"
	AuthRetryNointeract = "nointeract"
	AuthRetryInteract   = "interact"
)

// AuthRetryMode determines whether authentication failures are retryable.
type AuthRetryMode string

// ParseAuthRetryMode normalizes the auth-retry setting.
func ParseAuthRetryMode(value string) AuthRetryMode {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case AuthRetryNointeract:
		return AuthRetryNointeract
	case AuthRetryInteract:
		return AuthRetryInteract
	default:
		return AuthRetryNone
	}
}

// IsRetryable returns true if the AUTH_FAILED payload indicates a temporary
// failure that can be retried.
func IsRetryableAuthFailed(payload string) bool {
	upper := strings.ToUpper(strings.TrimSpace(payload))
	if !strings.HasPrefix(upper, "AUTH_FAILED") {
		return false
	}
	// AUTH_FAILED,TEMP indicates a temporary failure.
	return strings.HasPrefix(upper, "AUTH_FAILED,TEMP")
}

// AuthFailedError represents an authentication failure from the server.
type AuthFailedError struct {
	Reason    string
	Temporary bool
	RetryMode AuthRetryMode
}

func (e *AuthFailedError) Error() string {
	if e.Temporary && e.RetryMode != AuthRetryNone {
		return "openvpn auth failed (temporary, retrying): " + e.Reason
	}
	return "openvpn auth failed (terminal): " + e.Reason
}

// IsTerminal returns true if the failure is not retryable.
func (e *AuthFailedError) IsTerminal() bool {
	if !e.Temporary {
		return true
	}
	return e.RetryMode == AuthRetryNone
}

// ParseAuthFailed parses an AUTH_FAILED control message payload.
func ParseAuthFailed(payload string, retryMode AuthRetryMode) *AuthFailedError {
	payload = strings.TrimRight(payload, "\x00")
	upper := strings.ToUpper(strings.TrimSpace(payload))

	reason := ""
	temporary := false

	if strings.HasPrefix(upper, "AUTH_FAILED,TEMP") {
		temporary = true
		rest := payload[len("AUTH_FAILED,TEMP"):]
		// Strip [flags] prefix if present.
		rest = strings.TrimSpace(rest)
		if strings.HasPrefix(rest, "[") {
			if idx := strings.Index(rest, "]"); idx >= 0 {
				rest = strings.TrimSpace(rest[idx+1:])
			}
		}
		// Strip leading colon.
		rest = strings.TrimPrefix(rest, ":")
		rest = strings.TrimSpace(rest)
		reason = rest
	} else if strings.HasPrefix(upper, "AUTH_FAILED,") {
		reason = strings.TrimSpace(payload[len("AUTH_FAILED,"):])
	} else {
		reason = strings.TrimSpace(payload[len("AUTH_FAILED"):])
	}

	return &AuthFailedError{
		Reason:    reason,
		Temporary: temporary,
		RetryMode: retryMode,
	}
}

// ErrAuthFailed is returned when authentication fails terminally.
var ErrAuthFailed = errors.New("openvpn authentication failed")
