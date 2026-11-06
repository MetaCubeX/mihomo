package fakeip

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/profile/cachefile"

	"github.com/metacubex/bbolt"
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

	db, err := bbolt.Open(f.Name(), 0o666, &bbolt.Options{Timeout: time.Second, NoStatistics: true})
	if err != nil {
		return nil, "", err
	}

	pool.store = newCachefileStore(&cachefile.CacheFile{DB: db}, options.IPNet)
	return pool, f.Name(), nil
}

// createSharedCachefile opens a cache file that several pools can be built on,
// as the pools of a running config and of a reloaded one are
func createSharedCachefile(t *testing.T) *cachefile.CacheFile {
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0o666, &bbolt.Options{Timeout: time.Second, NoStatistics: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &cachefile.CacheFile{DB: db}
}

func newCachefilePool(t *testing.T, cache *cachefile.CacheFile, ipnet netip.Prefix) *Pool {
	pool, err := New(Options{IPNet: ipnet})
	if err != nil {
		t.Fatal(err)
	}
	pool.store = newCachefileStore(cache, ipnet)
	pool.restoreState()
	return pool
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

		assert.Equal(t, first, netip.AddrFrom4([4]byte{192, 168, 0, 4}))
		assert.Equal(t, pool.Lookup("foo.com"), netip.AddrFrom4([4]byte{192, 168, 0, 4}))
		assert.Equal(t, last, netip.AddrFrom4([4]byte{192, 168, 0, 5}))
		assert.True(t, exist)
		assert.Equal(t, bar, "bar.com")
		assert.Equal(t, pool.Gateway(), netip.AddrFrom4([4]byte{192, 168, 0, 1}))
		assert.Equal(t, pool.Broadcast(), netip.AddrFrom4([4]byte{192, 168, 0, 15}))
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

		assert.Equal(t, first, netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8804"))
		assert.Equal(t, pool.Lookup("foo.com"), netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8804"))
		assert.Equal(t, last, netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8805"))
		assert.True(t, exist)
		assert.Equal(t, bar, "bar.com")
		assert.Equal(t, pool.Gateway(), netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8801"))
		assert.Equal(t, pool.Broadcast(), netip.MustParseAddr("2001:4860:4860:0000:0000:0000:0000:8bff"))
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
		assert.Equal(t, foo, baz)
		assert.Equal(t, next, bar)
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

	assert.NotEqual(t, first, next)
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

	assert.NotEqual(t, bazIP, newBazIP)
}

func TestPool_Clone(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/24")
	pool, _ := New(Options{
		IPNet: ipnet,
		Size:  2,
	})

	first := pool.Lookup("foo.com")
	last := pool.Lookup("bar.com")
	assert.Equal(t, first, netip.AddrFrom4([4]byte{192, 168, 0, 4}))
	assert.Equal(t, last, netip.AddrFrom4([4]byte{192, 168, 0, 5}))

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

func TestPool_CloneKeepsAllocationState(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/24")
	pool, _ := New(Options{
		IPNet: ipnet,
		Size:  10,
	})

	foo := pool.Lookup("foo.com")
	bar := pool.Lookup("bar.com")

	newPool, _ := New(Options{
		IPNet: ipnet,
		Size:  10,
	})
	newPool.CloneFrom(pool)

	// a fresh allocation must not overwrite the retained mappings
	baz := newPool.Lookup("baz.com")
	assert.NotEqual(t, foo, baz)
	assert.NotEqual(t, bar, baz)
	assert.Equal(t, foo, newPool.Lookup("foo.com"))
	assert.Equal(t, bar, newPool.Lookup("bar.com"))
	host, ok := newPool.LookBack(foo)
	assert.True(t, ok)
	assert.Equal(t, "foo.com", host)
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

		assert.Equal(t, foo, fox)
		assert.Equal(t, foo, next)
		assert.NotEqual(t, foo, baz)
		assert.Equal(t, bar, bax)
		assert.Equal(t, bar, baz)
		assert.NotEqual(t, bar, next)
		assert.Equal(t, baz, nero)
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

	assert.Equal(t, foo, fox)
	assert.Equal(t, foo, next)
	assert.NotEqual(t, foo, baz)
	assert.Equal(t, bar, bax)
	assert.Equal(t, bar, baz)
	assert.NotEqual(t, bar, next)
	assert.Equal(t, baz, nero)
}

func TestPool_CloneKeepsCachefileMappings(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/24")
	cache := createSharedCachefile(t)

	// no offset is stored until shutdown, so the file holds mappings without one
	pool := newCachefilePool(t, cache, ipnet)
	foo := pool.Lookup("foo.com")

	// a reload builds the new pool while the old one is still serving
	newPool := newCachefilePool(t, cache, ipnet)

	host, exist := pool.LookBack(foo)
	assert.True(t, exist)
	assert.Equal(t, "foo.com", host)

	newPool.CloneFrom(pool)

	host, exist = newPool.LookBack(foo)
	assert.True(t, exist)
	assert.Equal(t, "foo.com", host)
	assert.Equal(t, foo, newPool.Lookup("foo.com"))
	assert.NotEqual(t, foo, newPool.Lookup("bar.com"))
}

func TestPool_OtherRangeFlushesCachefileOnUse(t *testing.T) {
	uses := map[string]func(pool *Pool, ip netip.Addr){
		"Lookup":   func(pool *Pool, ip netip.Addr) { pool.Lookup("bar.com") },
		"LookBack": func(pool *Pool, ip netip.Addr) { pool.LookBack(ip) },
		"Exist":    func(pool *Pool, ip netip.Addr) { pool.Exist(ip) },
	}

	for name, use := range uses {
		t.Run(name, func(t *testing.T) {
			cache := createSharedCachefile(t)
			pool := newCachefilePool(t, cache, netip.MustParsePrefix("192.168.0.1/24"))
			foo := pool.Lookup("foo.com")
			pool.StoreState()

			// the stored offset is outside the new range; building the pool must not
			// flush the file yet, the reload may still be rejected
			newPool := newCachefilePool(t, cache, netip.MustParsePrefix("192.168.1.1/24"))

			host, exist := pool.LookBack(foo)
			assert.True(t, exist)
			assert.Equal(t, "foo.com", host)

			newPool.CloneFrom(pool)
			use(newPool, foo)

			_, exist = pool.LookBack(foo)
			assert.False(t, exist)
			assert.True(t, newPool.IPNet().Contains(newPool.Lookup("foo.com")))
		})
	}
}

// with the flush deferred, a pool must still never use the mappings restoreState rejected
func TestPool_StaleCachefileIsFlushedBeforeUse(t *testing.T) {
	ipnet := netip.MustParsePrefix("192.168.0.1/24")
	cases := map[string]func(t *testing.T, cache *cachefile.CacheFile) *Pool{
		"new pool": func(t *testing.T, cache *cachefile.CacheFile) *Pool {
			return newCachefilePool(t, cache, ipnet)
		},
		"state stored before use": func(t *testing.T, cache *cachefile.CacheFile) *Pool {
			newCachefilePool(t, cache, ipnet).StoreState()
			return newCachefilePool(t, cache, ipnet)
		},
		"cloned from an unused pool": func(t *testing.T, cache *cachefile.CacheFile) *Pool {
			pool := newCachefilePool(t, cache, ipnet)
			newPool := newCachefilePool(t, cache, ipnet)
			newPool.CloneFrom(pool)
			return newPool
		},
		"cloned from a memory pool": func(t *testing.T, cache *cachefile.CacheFile) *Pool {
			pool, _ := New(Options{IPNet: ipnet, Size: 10})
			newPool := newCachefilePool(t, cache, ipnet)
			newPool.CloneFrom(pool)
			return newPool
		},
	}

	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			cache := createSharedCachefile(t)
			// a previous run that did not store its offset
			stale := newCachefilePool(t, cache, ipnet).Lookup("foo.com")

			pool := build(t, cache)
			assert.False(t, pool.Exist(stale))
			foo := pool.Lookup("foo.com")
			bar := pool.Lookup("bar.com")
			assert.NotEqual(t, foo, bar)
			host, exist := pool.LookBack(foo)
			assert.True(t, exist)
			assert.Equal(t, "foo.com", host)
		})
	}
}
