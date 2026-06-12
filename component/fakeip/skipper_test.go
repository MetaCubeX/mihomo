package fakeip

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"

	"github.com/stretchr/testify/assert"
)

func TestSkipper_BlackList(t *testing.T) {
	tree := trie.New[struct{}]()
	assert.NoError(t, tree.Insert("example.com", struct{}{}))
	assert.False(t, tree.IsEmpty())
	skipper := &Skipper{
		Host: []C.DomainMatcher{tree.NewDomainSet()},
	}
	assert.True(t, skipper.ShouldSkipped("example.com", netip.Addr{}))
	assert.False(t, skipper.ShouldSkipped("foo.com", netip.Addr{}))
	assert.False(t, skipper.shouldSkipped("baz.com"))
}

func TestSkipper_WhiteList(t *testing.T) {
	tree := trie.New[struct{}]()
	assert.NoError(t, tree.Insert("example.com", struct{}{}))
	assert.False(t, tree.IsEmpty())
	skipper := &Skipper{
		Host: []C.DomainMatcher{tree.NewDomainSet()},
		Mode: C.FilterWhiteList,
	}
	assert.False(t, skipper.ShouldSkipped("example.com", netip.Addr{}))
	assert.True(t, skipper.ShouldSkipped("foo.com", netip.Addr{}))
	assert.True(t, skipper.ShouldSkipped("baz.com", netip.Addr{}))
}

func TestSkipper_RuleSourceIPCIDR(t *testing.T) {
	rule, err := RC.NewIPCIDR("192.168.1.0/24", UseRealIP, RC.WithIPCIDRSourceIP(true), RC.WithIPCIDRNoResolve(true))
	assert.NoError(t, err)

	skipper := &Skipper{
		Rules: []C.Rule{rule},
	}

	assert.True(t, skipper.ShouldSkipped("example.com", netip.MustParseAddr("192.168.1.10")))
	assert.False(t, skipper.ShouldSkipped("example.com", netip.MustParseAddr("192.168.2.10")))
}
