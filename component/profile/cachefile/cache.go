package cachefile

import (
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/profile"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/bbolt"
)

var (
	initOnce     sync.Once
	fileMode     os.FileMode = 0o666
	defaultCache *CacheFile

	bucketSelected         = []byte("selected")
	bucketFakeip           = []byte("fakeip")
	bucketFakeip6          = []byte("fakeip6")
	bucketETag             = []byte("etag")
	bucketSubscriptionInfo = []byte("subscriptioninfo")
	bucketStorage          = []byte("storage")
	bucketNetworkPolicy    = []byte("networkpolicy")
)

// CacheFile store and update the cache file
type CacheFile struct {
	DB *bbolt.DB
}

func (c *CacheFile) SetSelected(group, selected string) {
	if !profile.StoreSelected.Load() {
		return
	} else if c.DB == nil {
		return
	}

	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketSelected)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(group), []byte(selected))
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
		return
	}
}

func (c *CacheFile) SelectedMap() map[string]string {
	if !profile.StoreSelected.Load() {
		return nil
	} else if c.DB == nil {
		return nil
	}

	mapping := map[string]string{}
	c.DB.View(func(t *bbolt.Tx) error {
		bucket := t.Bucket(bucketSelected)
		if bucket == nil {
			return nil
		}

		c := bucket.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			mapping[string(k)] = string(v)
		}
		return nil
	})
	return mapping
}

// SetNetworkPolicyState persists the per-group network-policy state machine
// record to bucketNetworkPolicy. Gated on profile.StoreSelected so that the
// network-policy state follows the same opt-in as the group's selected
// proxy: toggling StoreSelected off makes subsequent loads skip the bucket,
// so previously-persisted entries are effectively ignored (bbolt data
// itself is untouched until the next successful write or explicit delete).
//
// value is the caller-encoded JSON payload (see the networkpolicy package's
// internal persistence layer).
// Storing raw bytes here keeps the cachefile layer untangled from the
// networkpolicy package's schema.
func (c *CacheFile) SetNetworkPolicyState(group string, value []byte) {
	if !profile.StoreSelected.Load() {
		return
	} else if c.DB == nil {
		return
	}

	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketNetworkPolicy)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(group), value)
	})
	if err != nil {
		log.Warnln("[CacheFile] write network-policy state to %s failed: %s", c.DB.Path(), err.Error())
		return
	}
}

// DeleteNetworkPolicyState removes the entry for group from the bucket, used
// when a group's network-policy is removed via hot reload (orphan GC) or
// when the manager invalidates a corrupted record on load. No-op if the
// bucket or key does not exist.
//
// **Not gated on profile.StoreSelected**: orphan cleanup must work even
// when the user has toggled StoreSelected off between writes and deletes.
// Keeping a Delete no-op under the gate would leave stale entries around
// that resurrect when the user flips StoreSelected back on — the kind of
// silent regression architecture §5.6 explicitly avoids.
func (c *CacheFile) DeleteNetworkPolicyState(group string) {
	if c.DB == nil {
		return
	}

	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket := t.Bucket(bucketNetworkPolicy)
		if bucket == nil {
			return nil
		}
		return bucket.Delete([]byte(group))
	})
	if err != nil {
		log.Warnln("[CacheFile] delete network-policy state from %s failed: %s", c.DB.Path(), err.Error())
	}
}

// NetworkPolicyStateMap returns the full group → JSON-bytes map from
// bucketNetworkPolicy, along with a flag indicating whether the bucket
// actually exists on disk.
//
// Architecture §5.6.2 branch A / B hinges on **bucket existence**, not on
// whether the bucket has entries: an existing-but-empty bucket (e.g.,
// after every group's network-policy was removed and orphan-deleted) is
// still branch A for the groups currently declared. Callers must
// distinguish the two:
//
//	mapping, ok := cache.NetworkPolicyStateMap()
//	if !ok {
//	    // branch B: no bucket, cold start — evaluate on first PUT
//	} else {
//	    // branch A: bucket exists; groups not in `mapping` start fresh
//	    // (source=unknown, last_matched=nil) but still within branch A
//	}
//
// Returns (nil, false) when StoreSelected is off, the DB is unavailable,
// or the bucket has never been created — all three are equivalent to
// "no persisted state to restore" for the state machine. An empty but
// existing bucket returns (empty-map, true).
//
// Map values are copies of bbolt's tx-scoped slices so callers can retain
// the bytes past the View closure.
func (c *CacheFile) NetworkPolicyStateMap() (map[string][]byte, bool) {
	if !profile.StoreSelected.Load() {
		return nil, false
	} else if c.DB == nil {
		return nil, false
	}

	var (
		mapping      map[string][]byte
		bucketExists bool
	)
	c.DB.View(func(t *bbolt.Tx) error {
		bucket := t.Bucket(bucketNetworkPolicy)
		if bucket == nil {
			return nil
		}
		bucketExists = true
		mapping = map[string][]byte{}
		cur := bucket.Cursor()
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			// Copy v — bbolt reuses the slice once the tx ends.
			cp := make([]byte, len(v))
			copy(cp, v)
			mapping[string(k)] = cp
		}
		return nil
	})
	return mapping, bucketExists
}

func (c *CacheFile) Close() error {
	return c.DB.Close()
}

func initCache() {
	options := bbolt.Options{Timeout: time.Second}
	db, err := bbolt.Open(C.Path.Cache(), fileMode, &options)
	switch err {
	case bbolt.ErrInvalid, bbolt.ErrChecksum, bbolt.ErrVersionMismatch:
		if err = os.Remove(C.Path.Cache()); err != nil {
			log.Warnln("[CacheFile] remove invalid cache file error: %s", err.Error())
			break
		}
		log.Infoln("[CacheFile] remove invalid cache file and create new one")
		db, err = bbolt.Open(C.Path.Cache(), fileMode, &options)
	}
	if err != nil {
		log.Warnln("[CacheFile] can't open cache file: %s", err.Error())
	}

	defaultCache = &CacheFile{
		DB: db,
	}
}

// Cache return singleton of CacheFile
func Cache() *CacheFile {
	initOnce.Do(initCache)

	return defaultCache
}
