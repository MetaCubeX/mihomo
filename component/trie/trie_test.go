package trie

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIpv4AddSuccess(t *testing.T) {
	trie := NewIpCidrTrie()
	err := trie.AddIpCidrForString("10.0.0.2/16")
	assert.Equal(t, nil, err)
}

func TestIpv4AddFail(t *testing.T) {
	trie := NewIpCidrTrie()
	err := trie.AddIpCidrForString("333.00.23.2/23")
	assert.IsType(t, new(net.ParseError), err)

	err = trie.AddIpCidrForString("22.3.34.2/222")
	assert.IsType(t, new(net.ParseError), err)

	err = trie.AddIpCidrForString("2.2.2.2")
	assert.IsType(t, new(net.ParseError), err)
}

func TestIpv4Search(t *testing.T) {
	trie := NewIpCidrTrie()
	// Boundary testing
	assert.NoError(t, trie.AddIpCidrForString("149.154.160.0/20"))
	assert.Equal(t, true, trie.IsContainForString("149.154.160.0"))
	assert.Equal(t, true, trie.IsContainForString("149.154.175.255"))
	assert.Equal(t, false, trie.IsContainForString("149.154.176.0"))
	assert.Equal(t, false, trie.IsContainForString("149.154.159.255"))

	assert.NoError(t, trie.AddIpCidrForString("129.2.36.0/16"))
	assert.NoError(t, trie.AddIpCidrForString("10.2.36.0/18"))
	assert.NoError(t, trie.AddIpCidrForString("16.2.23.0/24"))
	assert.NoError(t, trie.AddIpCidrForString("11.2.13.2/26"))
	assert.NoError(t, trie.AddIpCidrForString("55.5.6.3/8"))
	assert.NoError(t, trie.AddIpCidrForString("66.23.25.4/6"))

	assert.Equal(t, true, trie.IsContainForString("129.2.3.65"))
	assert.Equal(t, false, trie.IsContainForString("15.2.3.1"))
	assert.Equal(t, true, trie.IsContainForString("11.2.13.1"))
	assert.Equal(t, true, trie.IsContainForString("55.0.0.0"))
	assert.Equal(t, true, trie.IsContainForString("64.0.0.0"))
	assert.Equal(t, false, trie.IsContainForString("128.0.0.0"))

	assert.Equal(t, false, trie.IsContain(net.ParseIP("22")))
	assert.Equal(t, false, trie.IsContain(net.ParseIP("")))

}

func TestIpv6AddSuccess(t *testing.T) {
	trie := NewIpCidrTrie()
	err := trie.AddIpCidrForString("2001:0db8:02de:0000:0000:0000:0000:0e13/32")
	assert.Equal(t, nil, err)

	err = trie.AddIpCidrForString("2001:1db8:f2de::0e13/18")
	assert.Equal(t, nil, err)
}

func TestIpv6AddFail(t *testing.T) {
	trie := NewIpCidrTrie()
	err := trie.AddIpCidrForString("2001::25de::cade/23")
	assert.IsType(t, new(net.ParseError), err)

	err = trie.AddIpCidrForString("2001:0fa3:25de::cade/222")
	assert.IsType(t, new(net.ParseError), err)

	err = trie.AddIpCidrForString("2001:0fa3:25de::cade")
	assert.IsType(t, new(net.ParseError), err)
}

func TestIpv6SearchSub(t *testing.T) {
	trie := NewIpCidrTrie()
	assert.NoError(t, trie.AddIpCidrForString("240e::/18"))

	assert.Equal(t, true, trie.IsContainForString("240e:964:ea02:100:1800::71"))

}

func TestIpv6Search(t *testing.T) {
	trie := NewIpCidrTrie()

	// Boundary testing
	assert.NoError(t, trie.AddIpCidrForString("2a0a:f280::/32"))
	assert.Equal(t, true, trie.IsContainForString("2a0a:f280:0000:0000:0000:0000:0000:0000"))
	assert.Equal(t, true, trie.IsContainForString("2a0a:f280:ffff:ffff:ffff:ffff:ffff:ffff"))
	assert.Equal(t, false, trie.IsContainForString("2a0a:f279:ffff:ffff:ffff:ffff:ffff:ffff"))
	assert.Equal(t, false, trie.IsContainForString("2a0a:f281:0000:0000:0000:0000:0000:0000"))

	assert.NoError(t, trie.AddIpCidrForString("2001:b28:f23d:f001::e/128"))
	assert.NoError(t, trie.AddIpCidrForString("2001:67c:4e8:f002::e/12"))
	assert.NoError(t, trie.AddIpCidrForString("2001:b28:f23d:f003::e/96"))
	assert.NoError(t, trie.AddIpCidrForString("2001:67c:4e8:f002::a/32"))
	assert.NoError(t, trie.AddIpCidrForString("2001:67c:4e8:f004::a/60"))
	assert.NoError(t, trie.AddIpCidrForString("2001:b28:f23f:f005::a/64"))
	assert.Equal(t, true, trie.IsContainForString("2001:b28:f23d:f001::e"))
	assert.Equal(t, false, trie.IsContainForString("2222::fff2"))
	assert.Equal(t, true, trie.IsContainForString("2000::ffa0"))
	assert.Equal(t, true, trie.IsContainForString("2001:b28:f23f:f005:5662::"))
	assert.Equal(t, true, trie.IsContainForString("2001:67c:4e8:9666::1213"))

	assert.Equal(t, false, trie.IsContain(net.ParseIP("22233:22")))
}

func TestIpv4InIpv6(t *testing.T) {
	trie := NewIpCidrTrie()

	// Boundary testing
	assert.NoError(t, trie.AddIpCidrForString("::ffff:198.18.5.138/128"))
}
