package defaultguard

import "testing"

func TestAllowScopesDefaultResolverEscapeHatch(t *testing.T) {
	base := allowCount.Load()
	release := Allow()
	if got := allowCount.Load(); got != base+1 {
		t.Fatalf("expected allow count to increment from %d to %d, got %d", base, base+1, got)
	}

	release()
	if got := allowCount.Load(); got != base {
		t.Fatalf("expected allow count to return to %d, got %d", base, got)
	}

	release()
	if got := allowCount.Load(); got != base {
		t.Fatalf("release should be idempotent, got allow count %d", got)
	}
}
