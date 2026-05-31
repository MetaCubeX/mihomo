package config

import (
	"testing"
)

func TestParseManagedConfig(t *testing.T) {
	tests := []struct {
		name string
		buf  string
		want ManagedConfig
	}{
		{
			name: "surge managed-config with options",
			buf:  "#!MANAGED-CONFIG https://example.com/sub interval=86400 strict=true\nmode: rule\n",
			want: ManagedConfig{URL: "https://example.com/sub", Interval: 86400, Strict: true},
		},
		{
			name: "surge managed-config url only",
			buf:  "#!MANAGED-CONFIG https://example.com/sub\nmode: rule\n",
			want: ManagedConfig{URL: "https://example.com/sub"},
		},
		{
			name: "stash subscribed",
			buf:  "#SUBSCRIBED https://example.com/sub\nmode: rule\n",
			want: ManagedConfig{URL: "https://example.com/sub"},
		},
		{
			name: "quoted url",
			buf:  "#SUBSCRIBED \"https://example.com/sub\"\nmode: rule\n",
			want: ManagedConfig{URL: "https://example.com/sub"},
		},
		{
			name: "directive after leading meta comments",
			buf:  "#!name=My Profile\n#!desc=demo\n#!MANAGED-CONFIG https://example.com/sub\nmode: rule\n",
			want: ManagedConfig{URL: "https://example.com/sub"},
		},
		{
			name: "leading blank lines",
			buf:  "\n\n#SUBSCRIBED https://example.com/sub\nmode: rule\n",
			want: ManagedConfig{URL: "https://example.com/sub"},
		},
		{
			name: "no directive",
			buf:  "mode: rule\nlog-level: info\n",
			want: ManagedConfig{},
		},
		{
			name: "plain comment is not a directive",
			buf:  "# just a comment\nmode: rule\n",
			want: ManagedConfig{},
		},
		{
			name: "directive in body is ignored",
			buf:  "mode: rule\n#SUBSCRIBED https://example.com/sub\n",
			want: ManagedConfig{},
		},
		{
			name: "keyword must be a whole token",
			buf:  "#SUBSCRIBEDFOO https://example.com/sub\nmode: rule\n",
			want: ManagedConfig{},
		},
		{
			name: "space after hash is a plain comment (subscribed)",
			buf:  "# SUBSCRIBED to this provider https://example.com/sub\nmode: rule\n",
			want: ManagedConfig{},
		},
		{
			name: "space after hash is a plain comment (managed-config)",
			buf:  "# !MANAGED-CONFIG explains the format https://example.com/sub\nmode: rule\n",
			want: ManagedConfig{},
		},
		{
			name: "case insensitive keyword",
			buf:  "#!managed-config https://example.com/sub interval=3600\nmode: rule\n",
			want: ManagedConfig{URL: "https://example.com/sub", Interval: 3600},
		},
		{
			name: "invalid interval ignored",
			buf:  "#!MANAGED-CONFIG https://example.com/sub interval=abc\nmode: rule\n",
			want: ManagedConfig{URL: "https://example.com/sub"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseManagedConfig([]byte(tt.buf))
			if got != tt.want {
				t.Fatalf("parseManagedConfig() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
