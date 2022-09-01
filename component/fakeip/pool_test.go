package fakeip

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/Dreamacro/clash/component/profile/cachefile"
	"github.com/Dreamacro/clash/component/trie"

	"github.com/stretchr/testify/assert"
	"go.etcd.io/bbolt"
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
	f, err := os.CreateTemp("", "clash")
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
	_, ipnet, _ := net.ParseCIDR("192.168.0.1/29")
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

		assert.True(t, first.Equal(net.IP{192, 168, 0, 2}))
		assert.Equal(t, pool.Lookup("foo.com"), net.IP{192, 168, 0, 2})
		assert.True(t, last.Equal(net.IP{192, 168, 0, 3}))
		assert.True(t, exist)
		assert.Equal(t, bar, "bar.com")
		assert.Equal(t, pool.Gateway(), net.IP{192, 168, 0, 1})
		assert.Equal(t, pool.IPNet().String(), ipnet.String())
		assert.True(t, pool.Exist(net.IP{192, 168, 0, 3}))
		assert.False(t, pool.Exist(net.IP{192, 168, 0, 4}))
		assert.False(t, pool.Exist(net.ParseIP("::1")))
	}
}

func TestPool_Case_Insensitive(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("192.168.0.1/29")
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

		assert.True(t, first.Equal(pool.Lookup("Foo.Com")))
		assert.Equal(t, pool.Lookup("fOo.cOM"), first)
		assert.True(t, exist)
		assert.Equal(t, foo, "foo.com")
	}
}

func TestPool_CycleUsed(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("192.168.0.1/29")
	pools, tempfile, err := createPools(Options{
		IPNet: ipnet,
		Size:  10,
	})
	assert.Nil(t, err)
	defer os.Remove(tempfile)

	for _, pool := range pools {
		assert.Equal(t, net.IP{192, 168, 0, 2}, pool.Lookup("2.com"))
		assert.Equal(t, net.IP{192, 168, 0, 3}, pool.Lookup("3.com"))
		assert.Equal(t, net.IP{192, 168, 0, 4}, pool.Lookup("4.com"))
		assert.Equal(t, net.IP{192, 168, 0, 5}, pool.Lookup("5.com"))
		assert.Equal(t, net.IP{192, 168, 0, 6}, pool.Lookup("6.com"))
		assert.Equal(t, net.IP{192, 168, 0, 2}, pool.Lookup("12.com"))
		assert.Equal(t, net.IP{192, 168, 0, 3}, pool.Lookup("3.com"))
	}
}

func TestPool_Skip(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("192.168.0.1/30")
	tree := trie.New()
	tree.Insert("example.com", tree)
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
	_, ipnet, _ := net.ParseCIDR("192.168.0.1/24")
	pool, _ := New(Options{
		IPNet: ipnet,
		Size:  2,
	})

	first := pool.Lookup("foo.com")
	pool.Lookup("bar.com")
	pool.Lookup("baz.com")
	next := pool.Lookup("foo.com")

	assert.False(t, first.Equal(next))
}

func TestPool_DoubleMapping(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("192.168.0.1/24")
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

	assert.False(t, bazIP.Equal(newBazIP))
}

func TestPool_Clone(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("192.168.0.1/24")
	pool, _ := New(Options{
		IPNet: ipnet,
		Size:  2,
	})

	first := pool.Lookup("foo.com")
	last := pool.Lookup("bar.com")
	assert.True(t, first.Equal(net.IP{192, 168, 0, 2}))
	assert.True(t, last.Equal(net.IP{192, 168, 0, 3}))

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
	_, ipnet, _ := net.ParseCIDR("192.168.0.1/31")
	_, err := New(Options{
		IPNet: ipnet,
		Size:  10,
	})

	assert.Error(t, err)
}
