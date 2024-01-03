package fakeip

import (
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/component/trie"

	"github.com/sagernet/bbolt"
	"github.com/stretchr/testify/assert"
)

func createPools(options Options) ([]*Pool, string, error) {
	pool, err := New(options)
	if err != nil {
		return nil, "", err
	}
	filePool, tempfile, err := createCachefileStore(options)
	if err != nil {
		return nil, "", err
	}

	return []*Pool{pool, filePool}, tempfile, nil
}

func createCachefileStore(options Options) (*Pool, string, error) {
	pool, err := New(options)
	if err != nil {
		return nil, "", err
	}
	f, err := os.CreateTemp("", "mihomo")
	if err != nil {
		return nil, "", err
	}

	db, err := bbolt.Open(f.Name(), 0o666, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, "", err
	}

	pool.store = &cachefileStore{
		cache: &cachefile.CacheFile{DB: db},
	}
	return pool, f.Name(), nil
}

func TestPool_Basic(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.0/28")
	pools, tempfile, err := createPools(Options{
		IPNet: ipnet,
		Size:  10,
	})
	assert.Nil(t, err)
	defer os.Remove(tempfile)

	for _, pool := range pools {
		first := pool.Lookup("foo.com")
		last := pool.Lookup("bar.com")
		bar, exist := pool.LookBack(last)

		assert.True(t, first == netip.AddrFrom4([4]byte{192, 168, 0, 4}))
		assert.True(t, pool.Lookup("foo.com") == netip.AddrFrom4([4]byte{192, 168, 0, 4}))
		assert.True(t, last == netip.AddrFrom4([4]byte{192, 168, 0, 5}))
		assert.True(t, exist)
		assert.Equal(t, bar, "bar.com")
		assert.True(t, pool.Gateway() == netip.AddrFrom4([4]byte{192, 168, 0, 1}))
		assert.True(t, pool.Broadcast() == netip.AddrFrom4([4]byte{192, 168, 0, 15}))
		assert.Equal(t, pool.IPNet().String(), ipnet.String())
		assert.True(t, pool.Exist(netip.AddrFrom4([4]byte{192, 168, 0, 5})))
		assert.False(t, pool.Exist(netip.AddrFrom4([4]byte{192, 168, 0, 6})))
		assert.False(t, pool.Exist(netip.MustParseAddr("::1")))
	}
}

func TestPool_BasicV6(t *testing.T) {
	ipnet := netip.MustParsePrefix("2001:4860:4860::8888/118")
	pools, tempfile, err := createPools(Options{
		IPNet: ipnet,
		Size:  10,
	})
	assert.Nil(t, err)
	defer os.Remove(tempfile)

	for _, pool := range pools {
		first := pool.Lookup("foo.com")
		last := pool.Lookup("bar.com")
		bar, exist := pool.LookBack(last)

		assert.True(t, first == netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8804"))
		assert.True(t, pool.Lookup("foo.com") == netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8804"))
		assert.True(t, last == netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8805"))
		assert.True(t, exist)
		assert.Equal(t, bar, "bar.com")
		assert.True(t, pool.Gateway() == netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8801"))
		assert.True(t, pool.Broadcast() == netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8bff"))
		assert.Equal(t, pool.IPNet().String(), ipnet.String())
		assert.True(t, pool.Exist(netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8805")))
		assert.False(t, pool.Exist(netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8806")))
		assert.False(t, pool.Exist(netip.MustParseAddr("127.0.0.1")))
	}
}

func TestPool_Case_Insensitive(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/29")
	pools, tempfile, err := createPools(Options{
		IPNet: ipnet,
		Size:  10,
	})
	assert.Nil(t, err)
	defer os.Remove(tempfile)

	for _, pool := range pools {
		first := pool.Lookup("foo.com")
		last := pool.Lookup("Foo.Com")
		foo, exist := pool.LookBack(last)

		assert.Equal(t, first, pool.Lookup("Foo.Com"))
		assert.Equal(t, pool.Lookup("fOo.cOM"), first)
		assert.True(t, exist)
		assert.Equal(t, foo, "foo.com")
	}
}

func TestPool_CycleUsed(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.16/28")
	pools, tempfile, err := createPools(Options{
		IPNet: ipnet,
		Size:  10,
	})
	assert.Nil(t, err)
	defer os.Remove(tempfile)

	for _, pool := range pools {
		foo := pool.Lookup("foo.com")
		bar := pool.Lookup("bar.com")
		for i := 0; i < 9; i++ {
			pool.Lookup(fmt.Sprintf("%d.com", i))
		}
		baz := pool.Lookup("baz.com")
		next := pool.Lookup("foo.com")
		assert.True(t, foo == baz)
		assert.True(t, next == bar)
	}
}

func TestPool_Skip(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/29")
	tree := trie.New[struct{}]()
	tree.Insert("example.com", struct{}{})
	pools, tempfile, err := createPools(Options{
		IPNet: ipnet,
		Size:  10,
		Host:  tree,
	})
	assert.Nil(t, err)
	defer os.Remove(tempfile)

	for _, pool := range pools {
		assert.True(t, pool.ShouldSkipped("example.com"))
		assert.False(t, pool.ShouldSkipped("foo.com"))
	}
}

func TestPool_MaxCacheSize(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/24")
	pool, _ := New(Options{
		IPNet: ipnet,
		Size:  2,
	})

	first := pool.Lookup("foo.com")
	pool.Lookup("bar.com")
	pool.Lookup("baz.com")
	next := pool.Lookup("foo.com")

	assert.False(t, first == next)
}

func TestPool_DoubleMapping(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/24")
	pool, _ := New(Options{
		IPNet: ipnet,
		Size:  2,
	})

	// fill cache
	fooIP := pool.Lookup("foo.com")
	bazIP := pool.Lookup("baz.com")

	// make foo.com hot
	pool.Lookup("foo.com")

	// should drop baz.com
	barIP := pool.Lookup("bar.com")

	_, fooExist := pool.LookBack(fooIP)
	_, bazExist := pool.LookBack(bazIP)
	_, barExist := pool.LookBack(barIP)

	newBazIP := pool.Lookup("baz.com")

	assert.True(t, fooExist)
	assert.False(t, bazExist)
	assert.True(t, barExist)

	assert.False(t, bazIP == newBazIP)
}

func TestPool_Clone(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/24")
	pool, _ := New(Options{
		IPNet: ipnet,
		Size:  2,
	})

	first := pool.Lookup("foo.com")
	last := pool.Lookup("bar.com")
	assert.True(t, first == netip.AddrFrom4([4]byte{192, 168, 0, 4}))
	assert.True(t, last == netip.AddrFrom4([4]byte{192, 168, 0, 5}))

	newPool, _ := New(Options{
		IPNet: ipnet,
		Size:  2,
	})
	newPool.CloneFrom(pool)
	_, firstExist := newPool.LookBack(first)
	_, lastExist := newPool.LookBack(last)
	assert.True(t, firstExist)
	assert.True(t, lastExist)
}

func TestPool_Error(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/31")
	_, err := New(Options{
		IPNet: ipnet,
		Size:  10,
	})

	assert.Error(t, err)
}

func TestPool_FlushFileCache(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/28")
	pools, tempfile, err := createPools(Options{
		IPNet: ipnet,
		Size:  10,
	})
	assert.Nil(t, err)
	defer os.Remove(tempfile)

	for _, pool := range pools {
		foo := pool.Lookup("foo.com")
		bar := pool.Lookup("baz.com")
		bax := pool.Lookup("baz.com")
		fox := pool.Lookup("foo.com")

		err = pool.FlushFakeIP()
		assert.Nil(t, err)

		next := pool.Lookup("baz.com")
		baz := pool.Lookup("foo.com")
		nero := pool.Lookup("foo.com")

		assert.True(t, foo == fox)
		assert.True(t, foo == next)
		assert.False(t, foo == baz)
		assert.True(t, bar == bax)
		assert.True(t, bar == baz)
		assert.False(t, bar == next)
		assert.True(t, baz == nero)
	}
}

func TestPool_FlushMemoryCache(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/28")
	pool, _ := New(Options{
		IPNet: ipnet,
		Size:  10,
	})

	foo := pool.Lookup("foo.com")
	bar := pool.Lookup("baz.com")
	bax := pool.Lookup("baz.com")
	fox := pool.Lookup("foo.com")

	err := pool.FlushFakeIP()
	assert.Nil(t, err)

	next := pool.Lookup("baz.com")
	baz := pool.Lookup("foo.com")
	nero := pool.Lookup("foo.com")

	assert.True(t, foo == fox)
	assert.True(t, foo == next)
	assert.False(t, foo == baz)
	assert.True(t, bar == bax)
	assert.True(t, bar == baz)
	assert.False(t, bar == next)
	assert.True(t, baz == nero)
}
