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

func TestShouldReportBlockedDefaultResolver(t *testing.T) {
	tests := []struct {
		count int64
		want  bool
	}{
		{count: 1, want: true},
		{count: 2, want: true},
		{count: 3, want: true},
		{count: 4, want: false},
		{count: 10, want: true},
		{count: 99, want: false},
		{count: 100, want: true},
		{count: 999, want: false},
		{count: 1000, want: true},
		{count: 1001, want: false},
	}

	for _, tc := range tests {
		if got := shouldReportBlockedDefaultResolver(tc.count); got != tc.want {
			t.Fatalf("shouldReportBlockedDefaultResolver(%d) = %t, want %t", tc.count, got, tc.want)
		}
	}
}
