package cache

import (
	"runtime"
	"sync"
	"time"
)

// Cache store element with a expired time
type Cache[K comparable, V any] struct {
	*cache[K, V]
}

type cache[K comparable, V any] struct {
	mapping sync.Map
	janitor *janitor[K, V]
}

type element[V any] struct {
	Expired time.Time
	Payload V
}

// Put element in Cache with its ttl
func (c *cache[K, V]) Put(key K, payload V, ttl time.Duration) {
	c.mapping.Store(key, &element[V]{
		Payload: payload,
		Expired: time.Now().Add(ttl),
	})
}

// Get element in Cache, and drop when it expired
func (c *cache[K, V]) Get(key K) V {
	item, exist := c.mapping.Load(key)
	if !exist {
		return getZero[V]()
	}
	elm := item.(*element[V])
	// expired
	if time.Since(elm.Expired) > 0 {
		c.mapping.Delete(key)
		return getZero[V]()
	}
	return elm.Payload
}

// GetWithExpire element in Cache with Expire Time
func (c *cache[K, V]) GetWithExpire(key K) (payload V, expired time.Time) {
	item, exist := c.mapping.Load(key)
	if !exist {
		return
	}
	elm := item.(*element[V])
	// expired
	if time.Since(elm.Expired) > 0 {
		c.mapping.Delete(key)
		return
	}
	return elm.Payload, elm.Expired
}

func (c *cache[K, V]) cleanup() {
	c.mapping.Range(func(k, v any) bool {
		key := k.(string)
		elm := v.(*element[V])
		if time.Since(elm.Expired) > 0 {
			c.mapping.Delete(key)
		}
		return true
	})
}

type janitor[K comparable, V any] struct {
	interval time.Duration
	stop     chan struct{}
}

func (j *janitor[K, V]) process(c *cache[K, V]) {
	ticker := time.NewTicker(j.interval)
	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-j.stop:
			ticker.Stop()
			return
		}
	}
}

func stopJanitor[K comparable, V any](c *Cache[K, V]) {
	c.janitor.stop <- struct{}{}
}

// New return *Cache
func New[K comparable, V any](interval time.Duration) *Cache[K, V] {
	j := &janitor[K, V]{
		interval: interval,
		stop:     make(chan struct{}),
	}
	c := &cache[K, V]{janitor: j}
	go j.process(c)
	C := &Cache[K, V]{c}
	runtime.SetFinalizer(C, stopJanitor[K, V])
	return C
}
