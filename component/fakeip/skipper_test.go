package fakeip

import (
	"testing"

	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
)

func TestSkipper_BlackList(t *testing.T) {
	tree := trie.New[struct{}]()
	assert.NoError(t, tree.Insert("example.com", struct{}{}))
	assert.False(t, tree.IsEmpty())
	skipper := &Skipper{
		Host: []C.DomainMatcher{tree.NewDomainSet()},
	}
	assert.True(t, skipper.ShouldSkipped("example.com"))
	assert.False(t, skipper.ShouldSkipped("foo.com"))
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
	assert.False(t, skipper.ShouldSkipped("example.com"))
	assert.True(t, skipper.ShouldSkipped("foo.com"))
	assert.True(t, skipper.ShouldSkipped("baz.com"))
}
