package openvpn

import (
	"testing"
)

func TestParseAuthRetryMode(t *testing.T) {
	tests := map[string]AuthRetryMode{
		"":           AuthRetryNone,
		"none":       AuthRetryNone,
		"nointeract": AuthRetryNointeract,
		"interact":   AuthRetryInteract,
		"NONE":       AuthRetryNone,
	}
	for input, want := range tests {
		got := ParseAuthRetryMode(input)
		if got != want {
			t.Errorf("ParseAuthRetryMode(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseAuthFailedTerminal(t *testing.T) {
	err := ParseAuthFailed("AUTH_FAILED", AuthRetryNone)
	if err == nil {
		t.Fatal("expected error")
	}
	if !err.IsTerminal() {
		t.Fatal("expected terminal failure")
	}
}

func TestParseAuthFailedWithReason(t *testing.T) {
	err := ParseAuthFailed("AUTH_FAILED,bad password", AuthRetryNone)
	if err.Reason != "bad password" {
		t.Fatalf("expected reason 'bad password', got %q", err.Reason)
	}
}

func TestParseAuthFailedTemporary(t *testing.T) {
	err := ParseAuthFailed("AUTH_FAILED,TEMP:server busy", AuthRetryNointeract)
	if !err.Temporary {
		t.Fatal("expected temporary failure")
	}
	if err.IsTerminal() {
		t.Fatal("expected non-terminal with nointeract retry mode")
	}
}

func TestParseAuthFailedTemporaryWithFlags(t *testing.T) {
	err := ParseAuthFailed("AUTH_FAILED,TEMP[backoff]:try again later", AuthRetryInteract)
	if !err.Temporary {
		t.Fatal("expected temporary failure")
	}
	if err.Reason != "try again later" {
		t.Fatalf("expected reason 'try again later', got %q", err.Reason)
	}
}

func TestParseAuthFailedTemporaryButNoneMode(t *testing.T) {
	err := ParseAuthFailed("AUTH_FAILED,TEMP:server busy", AuthRetryNone)
	if !err.Temporary {
		t.Fatal("expected temporary flag set")
	}
	if !err.IsTerminal() {
		t.Fatal("expected terminal when retry mode is none")
	}
}

func TestIsRetryableAuthFailed(t *testing.T) {
	if !IsRetryableAuthFailed("AUTH_FAILED,TEMP:retry") {
		t.Fatal("expected TEMP to be retryable")
	}
	if IsRetryableAuthFailed("AUTH_FAILED") {
		t.Fatal("expected plain AUTH_FAILED to not be retryable")
	}
	if IsRetryableAuthFailed("PUSH_REPLY") {
		t.Fatal("expected PUSH_REPLY to not be retryable")
	}
}
