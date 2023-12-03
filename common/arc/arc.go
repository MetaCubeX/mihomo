package arc

import (
	"sync"
	"time"

	list "github.com/bahlo/generic-list-go"
	"github.com/samber/lo"
)

//modify from https://github.com/alexanderGugel/arc

// Option is part of Functional Options Pattern
type Option[K comparable, V any] func(*ARC[K, V])

func WithSize[K comparable, V any](maxSize int) Option[K, V] {
	return func(a *ARC[K, V]) {
		a.c = maxSize
	}
}

type ARC[K comparable, V any] struct {
	p           int
	c           int
	t1          *list.List[*entry[K, V]]
	b1          *list.List[*entry[K, V]]
	t2          *list.List[*entry[K, V]]
	b2          *list.List[*entry[K, V]]
	mutex       sync.Mutex
	len         int
	cache       map[K]*entry[K, V]
	staleReturn bool
}

// New returns a new Adaptive Replacement Cache (ARC).
func New[K comparable, V any](options ...Option[K, V]) *ARC[K, V] {
	arc := &ARC[K, V]{
		p:     0,
		t1:    list.New[*entry[K, V]](),
		b1:    list.New[*entry[K, V]](),
		t2:    list.New[*entry[K, V]](),
		b2:    list.New[*entry[K, V]](),
		len:   0,
		cache: make(map[K]*entry[K, V]),
	}

	for _, option := range options {
		option(arc)
	}
	return arc
}

// Set inserts a new key-value pair into the cache.
// This optimizes future access to this entry (side effect).
func (a *ARC[K, V]) Set(key K, value V) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.set(key, value)
}

func (a *ARC[K, V]) set(key K, value V) {
	a.setWithExpire(key, value, time.Unix(0, 0))
}

// SetWithExpire stores any representation of a response for a given key and given expires.
// The expires time will round to second.
func (a *ARC[K, V]) SetWithExpire(key K, value V, expires time.Time) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.setWithExpire(key, value, expires)
}

func (a *ARC[K, V]) setWithExpire(key K, value V, expires time.Time) {
	ent, ok := a.cache[key]
	if ok != true {
		a.len++
		ent := &entry[K, V]{key: key, value: value, ghost: false, expires: expires.Unix()}
		a.req(ent)
		a.cache[key] = ent
	} else {
		if ent.ghost {
			a.len++
		}
		ent.value = value
		ent.ghost = false
		ent.expires = expires.Unix()
		a.req(ent)
	}
}

// Get retrieves a previously via Set inserted entry.
// This optimizes future access to this entry (side effect).
func (a *ARC[K, V]) Get(key K) (value V, ok bool) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	ent, ok := a.get(key)
	if ok {
		return ent.value, true
	}
	return lo.Empty[V](), false
}

func (a *ARC[K, V]) get(key K) (e *entry[K, V], ok bool) {
	ent, ok := a.cache[key]
	if ok {
		a.req(ent)
		return ent, !ent.ghost
	}
	return ent, false
}

// GetWithExpire returns any representation of a cached response,
// a time.Time Give expected expires,
// and a bool set to true if the key was found.
// This method will NOT check the maxAge of element and will NOT update the expires.
func (a *ARC[K, V]) GetWithExpire(key K) (V, time.Time, bool) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	ent, ok := a.get(key)
	if !ok {
		return lo.Empty[V](), time.Time{}, false
	}

	return ent.value, time.Unix(ent.expires, 0), true
}

// Len determines the number of currently cached entries.
// This method is side-effect free in the sense that it does not attempt to optimize random cache access.
func (a *ARC[K, V]) Len() int {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	return a.len
}

func (a *ARC[K, V]) req(ent *entry[K, V]) {
	if ent.ll == a.t1 || ent.ll == a.t2 {
		// Case I
		ent.setMRU(a.t2)
	} else if ent.ll == a.b1 {
		// Case II
		// Cache Miss in t1 and t2

		// Adaptation
		var d int
		if a.b1.Len() >= a.b2.Len() {
			d = 1
		} else {
			d = a.b2.Len() / a.b1.Len()
		}

		// a.p = min(a.p+d, a.c)
		a.p = a.p + d
		if a.c < a.p {
			a.p = a.c
		}

		a.replace(ent)
		ent.setMRU(a.t2)
	} else if ent.ll == a.b2 {
		// Case III
		// Cache Miss in t1 and t2

		// Adaptation
		var d int
		if a.b2.Len() >= a.b1.Len() {
			d = 1
		} else {
			d = a.b1.Len() / a.b2.Len()
		}
		//a.p = max(a.p-d, 0)
		a.p = a.p - d
		if a.p < 0 {
			a.p = 0
		}

		a.replace(ent)
		ent.setMRU(a.t2)
	} else if ent.ll == nil {
		// Case IV

		if a.t1.Len()+a.b1.Len() == a.c {
			// Case A
			if a.t1.Len() < a.c {
				a.delLRU(a.b1)
				a.replace(ent)
			} else {
				a.delLRU(a.t1)
			}
		} else if a.t1.Len()+a.b1.Len() < a.c {
			// Case B
			if a.t1.Len()+a.t2.Len()+a.b1.Len()+a.b2.Len() >= a.c {
				if a.t1.Len()+a.t2.Len()+a.b1.Len()+a.b2.Len() == 2*a.c {
					a.delLRU(a.b2)
				}
				a.replace(ent)
			}
		}

		ent.setMRU(a.t1)
	}
}

func (a *ARC[K, V]) delLRU(list *list.List[*entry[K, V]]) {
	lru := list.Back()
	list.Remove(lru)
	a.len--
	delete(a.cache, lru.Value.key)
}

func (a *ARC[K, V]) replace(ent *entry[K, V]) {
	if a.t1.Len() > 0 && ((a.t1.Len() > a.p) || (ent.ll == a.b2 && a.t1.Len() == a.p)) {
		lru := a.t1.Back().Value
		lru.value = lo.Empty[V]()
		lru.ghost = true
		a.len--
		lru.setMRU(a.b1)
	} else {
		lru := a.t2.Back().Value
		lru.value = lo.Empty[V]()
		lru.ghost = true
		a.len--
		lru.setMRU(a.b2)
	}
}
