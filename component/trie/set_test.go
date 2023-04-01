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
		"test.a.net",
		"test.a.oc",
	}
	set := trie.NewDomainSet(domainSet)
	assert.NotNil(t, set)
	assert.True(t, set.Has("test.a.net"))
	assert.True(t, set.Has("google.com"))
	assert.False(t, set.Has("www.baidu.com"))
}

func TestDomainComplexWildcard(t *testing.T) {
	domainSet := []string{
		"+.baidu.com",
		"+.a.baidu.com",
		"www.baidu.com",
		"+.bb.baidu.com",
		"test.a.net",
		"test.a.oc",
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
		"*.*.*.baidu.com",
		"www.baidu.*",
		"stun.*.*",
		"*.*.qq.com",
		"test.*.baidu.com",
	}
	set := trie.NewDomainSet(domainSet)
	assert.NotNil(t, set)
	assert.True(t, set.Has("www.baidu.com"))
	assert.True(t, set.Has("test.test.baidu.com"))
	assert.True(t, set.Has("test.test.qq.com"))
	assert.True(t,set.Has("stun.ab.cd"))
	assert.False(t, set.Has("test.baidu.com"))
	assert.False(t,set.Has("www.google.com"))
	assert.False(t, set.Has("test.qq.com"))
	assert.False(t, set.Has("test.test.test.qq.com"))
}
