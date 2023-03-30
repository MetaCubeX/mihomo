package trie_test

import (
	"testing"

	"github.com/Dreamacro/clash/component/trie"
	"github.com/stretchr/testify/assert"
)

func TestDomain(t *testing.T) {
	domainSet := []string{
		"baidu.com",
		"google.com",
		"www.google.com",
	}
	set := trie.NewDomainSet(domainSet)
	assert.NotNil(t, set)
	assert.True(t, set.Has("google.com"))
	assert.False(t, set.Has("www.baidu.com"))
}

func TestDomainComplexWildcard(t *testing.T) {
	domainSet := []string{
		"+.baidu.com",
		"+.a.baidu.com",
		"www.baidu.com",
		"www.qq.com",
	}
	set := trie.NewDomainSet(domainSet)
	assert.NotNil(t, set)
	assert.False(t, set.Has("google.com"))
	assert.True(t, set.Has("www.baidu.com"))
	assert.True(t, set.Has("test.test.baidu.com"))
}

func TestDomainWildcard(t *testing.T) {
	domainSet := []string{
		"*.baidu.com",
		"www.baidu.com",
		"*.*.qq.com",
	}
	set := trie.NewDomainSet(domainSet)
	assert.NotNil(t, set)
	// assert.True(t, set.Has("www.baidu.com"))
	// assert.False(t, set.Has("test.test.baidu.com"))
	assert.True(t,set.Has("test.test.qq.com"))
	assert.False(t,set.Has("test.qq.com"))
	assert.False(t,set.Has("test.test.test.qq.com"))
}
