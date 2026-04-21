package networkpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeMAC(t *testing.T) {
	const want = "aa:bb:cc:dd:ee:ff"
	valid := []string{
		"aa:bb:cc:dd:ee:ff",
		"AA:BB:CC:DD:EE:FF",
		"aa-bb-cc-dd-ee-ff",
		"AA-BB-CC-DD-EE-FF",
		"aabbccddeeff",
		"AABBCCDDEEFF",
	}
	for _, in := range valid {
		got, err := normalizeMAC(in)
		assert.NoError(t, err, "input=%q", in)
		assert.Equal(t, want, got, "input=%q", in)
		// idempotent
		again, err := normalizeMAC(got)
		assert.NoError(t, err)
		assert.Equal(t, got, again)
	}

	invalid := []string{
		"",
		"aa:bb:cc:dd:ee",       // 5 groups
		"aa:bb:cc:dd:ee:ff:11", // 7 groups
		"aa:bb:cc:dd:ee:zz",    // non-hex
		"aa:bb-cc:dd-ee:ff",    // mixed separators
		"aabb.ccdd.eeff",       // unknown grouping
		"aabbccddeefg",         // unseparated non-hex
		"aaabbbcccdddeeefff",   // wrong length
		"aa:bbb:cc:dd:ee:ff",   // wrong group width
	}
	for _, in := range invalid {
		_, err := normalizeMAC(in)
		assert.Error(t, err, "input=%q", in)
	}
}

func TestMeteredString(t *testing.T) {
	b := true
	f := false
	assert.Equal(t, "null", meteredString(nil))
	assert.Equal(t, "true", meteredString(&b))
	assert.Equal(t, "false", meteredString(&f))
}

func TestNormalizeDNSSuffix(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil stays nil", nil, nil},
		{"empty stays nil", []string{}, nil},
		{"all-empty strings stay nil", []string{"", ""}, nil},
		{"single entry lowercased", []string{"Corp.Example.COM"}, []string{"corp.example.com"}},
		{"sort + dedup + lowercase", []string{"CORP", "home", "corp", ""}, []string{"corp", "home"}},
	}
	for _, tc := range cases {
		got := normalizeDNSSuffix(tc.in)
		assert.Equal(t, tc.want, got, "case %q", tc.name)
	}
}
