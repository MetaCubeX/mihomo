package trie_test

import (
	"strconv"
	"strings"
	"testing"

	"golang.org/x/exp/slices"

	"github.com/metacubex/mihomo/component/trie"
	"github.com/stretchr/testify/assert"
)

func testDump(t *testing.T, tree *trie.DomainTrie[struct{}], set *trie.DomainSet) {
	var dataSrc []string
	tree.Foreach(func(domain string, data struct{}) bool {
		dataSrc = append(dataSrc, domain)
		return true
	})
	slices.Sort(dataSrc)
	var dataSet []string
	set.Foreach(func(key string) bool {
		dataSet = append(dataSet, key)
		return true
	})
	slices.Sort(dataSet)
	assert.Equal(t, dataSrc, dataSet)
}

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
	assert.False(t, tree.IsEmpty())
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
	testDump(t, tree, set)
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
	assert.False(t, tree.IsEmpty())
	set := tree.NewDomainSet()
	assert.NotNil(t, set)
	assert.False(t, set.Has("google.com"))
	assert.True(t, set.Has("www.baidu.com"))
	assert.True(t, set.Has("test.test.baidu.com"))
	testDump(t, tree, set)
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
	assert.False(t, tree.IsEmpty())
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
	testDump(t, tree, set)
}

func TestDomainSetCase(t *testing.T) {
	tree := trie.New[struct{}]()
	for _, domain := range []string{"example.com", "+.mixed.example.org"} {
		assert.NoError(t, tree.Insert(domain, struct{}{}))
	}
	set := tree.NewDomainSet()
	assert.NotNil(t, set)
	assert.True(t, set.Has("EXAMPLE.COM"))
	assert.True(t, set.Has("ExAmPlE.cOm"))
	assert.True(t, set.Has("WWW.MIXED.EXAMPLE.ORG"))
	assert.False(t, set.Has("EXAMPLE.NET"))
}

// TestDomainSetUnicode covers keys that are not ASCII, which take a different
// path than the byte-wise one because the set is built with rune-wise reversal.
func TestDomainSetUnicode(t *testing.T) {
	tree := trie.New[struct{}]()
	for _, domain := range []string{"中文.example", "+.测试.cn"} {
		assert.NoError(t, tree.Insert(domain, struct{}{}))
	}
	set := tree.NewDomainSet()
	assert.NotNil(t, set)
	assert.True(t, set.Has("中文.example"))
	assert.True(t, set.Has("www.测试.cn"))
	assert.False(t, set.Has("日本語.example"))
}

func TestDomainSetOversizedKey(t *testing.T) {
	tree := trie.New[struct{}]()
	assert.NoError(t, tree.Insert("+.example.com", struct{}{}))
	set := tree.NewDomainSet()
	assert.NotNil(t, set)

	var builder strings.Builder
	for builder.Len() < 300 {
		builder.WriteString("label.")
	}
	assert.True(t, set.Has(builder.String()+"example.com"))
	assert.False(t, set.Has(builder.String()+"example.net"))
}

func BenchmarkDomainSetHas(b *testing.B) {
	tree := trie.New[struct{}]()
	for i := 0; i < 10000; i++ {
		assert.NoError(b, tree.Insert("+."+strconv.Itoa(i)+".example.com", struct{}{}))
	}
	set := tree.NewDomainSet()

	// Keys are split by length because the Go compiler only keeps a
	// non-constant sized allocation off the heap up to 32 bytes, so hostnames
	// longer than that used to take a different path.
	benchmarks := []struct {
		name string
		keys []string
	}{
		{"short", []string{
			"www.4242.example.com",
			"a.b.c.9999.example.com",
			"no-such-host.example.net",
			"WWW.1234.EXAMPLE.COM",
		}},
		{"long", []string{
			"ec2-52-201-13-44.compute-1.4242.example.com",
			"prod-eu-west-1-api.metrics.9999.example.com",
			"abcdef123456.dualstack.us-east-1.elb.example.net",
			"EC2-52-201-13-44.COMPUTE-1.1234.EXAMPLE.COM",
		}},
	}
	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				set.Has(benchmark.keys[i%len(benchmark.keys)])
			}
		})
	}
}
