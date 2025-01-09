package cachefile

import (
	"net/netip"

	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/bbolt"
)

type FakeIpStore struct {
	*CacheFile
}

func (c *CacheFile) FakeIpStore() *FakeIpStore {
	return &FakeIpStore{c}
}

func (c *FakeIpStore) GetByHost(host string) (ip netip.Addr, exist bool) {
	if c.DB == nil {
		return
	}
	c.DB.View(func(t *bbolt.Tx) error {
		if bucket := t.Bucket(bucketFakeip); bucket != nil {
			if v := bucket.Get([]byte(host)); v != nil {
				ip, exist = netip.AddrFromSlice(v)
			}
		}
		return nil
	})
	return
}

func (c *FakeIpStore) PutByHost(host string, ip netip.Addr) {
	if c.DB == nil {
		return
	}
	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketFakeip)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(host), ip.AsSlice())
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
	}
}

func (c *FakeIpStore) GetByIP(ip netip.Addr) (host string, exist bool) {
	if c.DB == nil {
		return
	}
	c.DB.View(func(t *bbolt.Tx) error {
		if bucket := t.Bucket(bucketFakeip); bucket != nil {
			if v := bucket.Get(ip.AsSlice()); v != nil {
				host, exist = string(v), true
			}
		}
		return nil
	})
	return
}

func (c *FakeIpStore) PutByIP(ip netip.Addr, host string) {
	if c.DB == nil {
		return
	}
	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketFakeip)
		if err != nil {
			return err
		}
		return bucket.Put(ip.AsSlice(), []byte(host))
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
	}
}

func (c *FakeIpStore) DelByIP(ip netip.Addr) {
	if c.DB == nil {
		return
	}

	addr := ip.AsSlice()
	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketFakeip)
		if err != nil {
			return err
		}
		host := bucket.Get(addr)
		err = bucket.Delete(addr)
		if len(host) > 0 {
			if err = bucket.Delete(host); err != nil {
				return err
			}
		}
		return err
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
	}
}

func (c *FakeIpStore) FlushFakeIP() error {
	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket := t.Bucket(bucketFakeip)
		if bucket == nil {
			return nil
		}
		return t.DeleteBucket(bucketFakeip)
	})
	return err
}
