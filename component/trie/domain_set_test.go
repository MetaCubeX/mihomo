package trie_test

import (
	"testing"

	"github.com/metacubex/mihomo/component/trie"
	"github.com/stretchr/testify/assert"
)

func TestDomainSet(t *testing.T) {
	tree := trie.New[struct{}]()
	domainSet := []string{
		"baidu.com",
		"google.com",
		"www.google.com",
		"test.a.net",
		"test.a.oc",
		"Mijia Cloud",
		".qq.com",
		"+.cn",
	}

	for _, domain := range domainSet {
		assert.NoError(t, tree.Insert(domain, struct{}{}))
	}
	set := tree.NewDomainSet()
	assert.NotNil(t, set)
	assert.True(t, set.Has("test.cn"))
	assert.True(t, set.Has("cn"))
	assert.True(t, set.Has("Mijia Cloud"))
	assert.True(t, set.Has("test.a.net"))
	assert.True(t, set.Has("www.qq.com"))
	assert.True(t, set.Has("google.com"))
	assert.False(t, set.Has("qq.com"))
	assert.False(t, set.Has("www.baidu.com"))
}

func TestDomainSetComplexWildcard(t *testing.T) {
	tree := trie.New[struct{}]()
	domainSet := []string{
		"+.baidu.com",
		"+.a.baidu.com",
		"www.baidu.com",
		"+.bb.baidu.com",
		"test.a.net",
		"test.a.oc",
		"www.qq.com",
	}

	for _, domain := range domainSet {
		assert.NoError(t, tree.Insert(domain, struct{}{}))
	}
	set := tree.NewDomainSet()
	assert.NotNil(t, set)
	assert.False(t, set.Has("google.com"))
	assert.True(t, set.Has("www.baidu.com"))
	assert.True(t, set.Has("test.test.baidu.com"))
}

func TestDomainSetWildcard(t *testing.T) {
	tree := trie.New[struct{}]()
	domainSet := []string{
		"*.*.*.baidu.com",
		"www.baidu.*",
		"stun.*.*",
		"*.*.qq.com",
		"test.*.baidu.com",
		"*.apple.com",
	}

	for _, domain := range domainSet {
		assert.NoError(t, tree.Insert(domain, struct{}{}))
	}
	set := tree.NewDomainSet()
	assert.NotNil(t, set)
	assert.True(t, set.Has("www.baidu.com"))
	assert.True(t, set.Has("test.test.baidu.com"))
	assert.True(t, set.Has("test.test.qq.com"))
	assert.True(t, set.Has("stun.ab.cd"))
	assert.False(t, set.Has("test.baidu.com"))
	assert.False(t, set.Has("www.google.com"))
	assert.False(t, set.Has("a.www.google.com"))
	assert.False(t, set.Has("test.qq.com"))
	assert.False(t, set.Has("test.test.test.qq.com"))
}
