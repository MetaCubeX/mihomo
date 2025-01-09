package cachefile

import (
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/bbolt"
	"github.com/vmihailenco/msgpack/v5"
)

type EtagWithHash struct {
	Hash utils.HashType
	ETag string
	Time time.Time
}

func (c *CacheFile) SetETagWithHash(url string, etagWithHash EtagWithHash) {
	if c.DB == nil {
		return
	}

	data, err := msgpack.Marshal(etagWithHash)
	if err != nil {
		return // maybe panic is better
	}

	err = c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketETag)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(url), data)
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
		return
	}
}
func (c *CacheFile) GetETagWithHash(key string) (etagWithHash EtagWithHash) {
	if c.DB == nil {
		return
	}
	c.DB.View(func(t *bbolt.Tx) error {
		if bucket := t.Bucket(bucketETag); bucket != nil {
			if v := bucket.Get([]byte(key)); v != nil {
				if err := msgpack.Unmarshal(v, &etagWithHash); err != nil {
					return err
				}
			}
		}
		return nil
	})

	return
}
