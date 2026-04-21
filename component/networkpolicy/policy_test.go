package networkpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGroupPolicy_IsEmpty(t *testing.T) {
	assert.True(t, GroupPolicy{}.IsEmpty())
	assert.False(t, GroupPolicy{Mapping: map[string]string{"office": "hk"}}.IsEmpty())
	assert.False(t, GroupPolicy{HasDefault: true, DefaultProxy: "direct"}.IsEmpty())
}

func TestGroupPolicy_Resolve(t *testing.T) {
	withDefault := GroupPolicy{
		Mapping:      map[string]string{"office": "hk"},
		HasDefault:   true,
		DefaultProxy: "direct",
	}
	noDefault := GroupPolicy{Mapping: map[string]string{"office": "hk"}}

	cases := []struct {
		name       string
		p          GroupPolicy
		matched    string
		wantTarget string
		wantReason string
	}{
		{"matched mapping", withDefault, "office", "hk", ReasonMatched},
		{"unmapped network falls to default", withDefault, "unknown", "direct", ReasonDefault},
		{"empty match falls to default", withDefault, "", "direct", ReasonDefault},
		{"no mapping no default", noDefault, "", "", ReasonNoChangeNoDefault},
		{"unknown no default", noDefault, "unknown", "", ReasonNoChangeNoDefault},
	}
	for _, tc := range cases {
		target, reason := tc.p.Resolve(tc.matched)
		assert.Equal(t, tc.wantTarget, target, tc.name)
		assert.Equal(t, tc.wantReason, reason, tc.name)
	}
}
