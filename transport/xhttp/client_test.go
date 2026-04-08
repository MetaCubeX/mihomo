package xhttp

import "testing"

func TestShouldUseHTTP3(t *testing.T) {
	tests := []struct {
		name     string
		alpn     []string
		tryQUIC  bool
		expected bool
	}{
		{name: "disabled", alpn: []string{"h3"}, tryQUIC: false, expected: false},
		{name: "enabled-h3", alpn: []string{"h3"}, tryQUIC: true, expected: true},
		{name: "enabled-no-h3", alpn: []string{"h2", "http/1.1"}, tryQUIC: true, expected: false},
		{name: "enabled-empty", alpn: nil, tryQUIC: true, expected: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldUseHTTP3(tc.alpn, tc.tryQUIC); got != tc.expected {
				t.Fatalf("shouldUseHTTP3(%v, %t) = %t, want %t", tc.alpn, tc.tryQUIC, got, tc.expected)
			}
		})
	}
}
