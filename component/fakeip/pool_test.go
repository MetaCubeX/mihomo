package fakeip

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPool_Basic(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("192.168.0.1/29")
	pool, _ := New(ipnet, 10, nil)

	first := pool.Lookup("foo.com")
	last := pool.Lookup("bar.com")
	bar, exist := pool.LookBack(last)

	assert.True(t, first.Equal(net.IP{192, 168, 0, 2}))
	assert.True(t, last.Equal(net.IP{192, 168, 0, 3}))
	assert.True(t, exist)
	assert.Equal(t, bar, "bar.com")
}

func TestPool_Cycle(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("192.168.0.1/30")
	pool, _ := New(ipnet, 10, nil)

	first := pool.Lookup("foo.com")
	same := pool.Lookup("baz.com")

	assert.True(t, first.Equal(same))
}

func TestPool_MaxCacheSize(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("192.168.0.1/24")
	pool, _ := New(ipnet, 2, nil)

	first := pool.Lookup("foo.com")
	pool.Lookup("bar.com")
	pool.Lookup("baz.com")
	next := pool.Lookup("foo.com")

	assert.False(t, first.Equal(next))
}

func TestPool_DoubleMapping(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("192.168.0.1/24")
	pool, _ := New(ipnet, 2, nil)

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

func TestPool_Error(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("192.168.0.1/31")
	_, err := New(ipnet, 10, nil)

	assert.Error(t, err)
}
