package trie_test

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/trie"
	"github.com/stretchr/testify/assert"
)

var localIP = netip.AddrFrom4([4]byte{127, 0, 0, 1})

func TestTrie_Basic(t *testing.T) {
	tree := trie.New[netip.Addr]()
	domains := []string{
		"example.com",
		"google.com",
		"localhost",
	}

	for _, domain := range domains {
		assert.NoError(t, tree.Insert(domain, localIP))
	}

	node := tree.Search("example.com")
	assert.NotNil(t, node)
	assert.True(t, node.Data() == localIP)
	assert.NotNil(t, tree.Insert("", localIP))
	assert.Nil(t, tree.Search(""))
	assert.NotNil(t, tree.Search("localhost"))
	assert.Nil(t, tree.Search("www.google.com"))
}

func TestTrie_Wildcard(t *testing.T) {
	tree := trie.New[netip.Addr]()
	domains := []string{
		"*.example.com",
		"sub.*.example.com",
		"*.dev",
		".org",
		".example.net",
		".apple.*",
		"+.foo.com",
		"+.stun.*.*",
		"+.stun.*.*.*",
		"+.stun.*.*.*.*",
		"stun.l.google.com",
	}

	for _, domain := range domains {
		assert.NoError(t, tree.Insert(domain, localIP))
	}

	assert.NotNil(t, tree.Search("sub.example.com"))
	assert.NotNil(t, tree.Search("sub.foo.example.com"))
	assert.NotNil(t, tree.Search("test.org"))
	assert.NotNil(t, tree.Search("test.example.net"))
	assert.NotNil(t, tree.Search("test.apple.com"))
	assert.NotNil(t, tree.Search("test.foo.com"))
	assert.NotNil(t, tree.Search("foo.com"))
	assert.NotNil(t, tree.Search("global.stun.website.com"))
	assert.Nil(t, tree.Search("foo.sub.example.com"))
	assert.Nil(t, tree.Search("foo.example.dev"))
	assert.Nil(t, tree.Search("example.com"))
}

func TestTrie_Priority(t *testing.T) {
	tree := trie.New[int]()
	domains := []string{
		".dev",
		"example.dev",
		"*.example.dev",
		"test.example.dev",
	}

	assertFn := func(domain string, data int) {
		node := tree.Search(domain)
		assert.NotNil(t, node)
		assert.Equal(t, data, node.Data())
	}

	for idx, domain := range domains {
		assert.NoError(t, tree.Insert(domain, idx+1))
	}

	assertFn("test.dev", 1)
	assertFn("foo.bar.dev", 1)
	assertFn("example.dev", 2)
	assertFn("foo.example.dev", 3)
	assertFn("test.example.dev", 4)
}

func TestTrie_Boundary(t *testing.T) {
	tree := trie.New[netip.Addr]()
	assert.NoError(t, tree.Insert("*.dev", localIP))

	assert.NotNil(t, tree.Insert(".", localIP))
	assert.NotNil(t, tree.Insert("..dev", localIP))
	assert.Nil(t, tree.Search("dev"))
}

func TestTrie_WildcardBoundary(t *testing.T) {
	tree := trie.New[netip.Addr]()
	assert.NoError(t, tree.Insert("+.*", localIP))
	assert.NoError(t, tree.Insert("stun.*.*.*", localIP))

	assert.NotNil(t, tree.Search("example.com"))
}

func TestTrie_Foreach(t *testing.T) {
	tree := trie.New[netip.Addr]()
	domainList := []string{
		"google.com",
		"stun.*.*.*",
		"test.*.google.com",
		"+.baidu.com",
		"*.baidu.com",
		"*.*.baidu.com",
	}
	for _, domain := range domainList {
		assert.NoError(t, tree.Insert(domain, localIP))
	}
	count := 0
	tree.Foreach(func(domain string, data netip.Addr) {
		count++
	})
	assert.Equal(t, 7, count)
}
