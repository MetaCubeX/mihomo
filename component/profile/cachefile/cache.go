package cachefile

import (
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/profile"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/sagernet/bbolt"
)

var (
	initOnce     sync.Once
	fileMode     os.FileMode = 0o666
	defaultCache *CacheFile

	bucketSelected = []byte("selected")
	bucketFakeip   = []byte("fakeip")
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

func (c *CacheFile) PutFakeip(key, value []byte) error {
	if c.DB == nil {
		return nil
	}

	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketFakeip)
		if err != nil {
			return err
		}
		return bucket.Put(key, value)
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
	}

	return err
}

func (c *CacheFile) DelFakeipPair(ip, host []byte) error {
	if c.DB == nil {
		return nil
	}

	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketFakeip)
		if err != nil {
			return err
		}
		err = bucket.Delete(ip)
		if len(host) > 0 {
			if err := bucket.Delete(host); err != nil {
				return err
			}
		}
		return err
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
	}

	return err
}

func (c *CacheFile) GetFakeip(key []byte) []byte {
	if c.DB == nil {
		return nil
	}

	tx, err := c.DB.Begin(false)
	if err != nil {
		return nil
	}
	defer tx.Rollback()

	bucket := tx.Bucket(bucketFakeip)
	if bucket == nil {
		return nil
	}

	return bucket.Get(key)
}

func (c *CacheFile) FlushFakeIP() error {
	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket := t.Bucket(bucketFakeip)
		if bucket == nil {
			return nil
		}
		return t.DeleteBucket(bucketFakeip)
	})
	return err
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
