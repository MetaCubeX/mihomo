package fakeip

import (
	"net"
	"testing"
)

func TestPool_Basic(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("192.168.0.1/30")
	pool, _ := New(ipnet)

	first := pool.Get()
	last := pool.Get()

	if !first.Equal(net.IP{192, 168, 0, 1}) {
		t.Error("should get right first ip, instead of", first.String())
	}

	if !last.Equal(net.IP{192, 168, 0, 2}) {
		t.Error("should get right last ip, instead of", first.String())
	}
}

func TestPool_Cycle(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("192.168.0.1/30")
	pool, _ := New(ipnet)

	first := pool.Get()
	pool.Get()
	same := pool.Get()

	if !first.Equal(same) {
		t.Error("should return same ip", first.String())
	}
}

func TestPool_Error(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("192.168.0.1/31")
	_, err := New(ipnet)

	if err == nil {
		t.Error("should return err")
	}
}
