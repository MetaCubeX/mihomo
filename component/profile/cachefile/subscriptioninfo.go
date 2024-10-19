package cachefile

import (
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/bbolt"
)

func (c *CacheFile) SetSubscriptionInfo(name string, userInfo string) {
	if c.DB == nil {
		return
	}

	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketSubscriptionInfo)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(name), []byte(userInfo))
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
		return
	}
}
func (c *CacheFile) GetSubscriptionInfo(name string) (userInfo string) {
	if c.DB == nil {
		return
	}
	c.DB.View(func(t *bbolt.Tx) error {
		if bucket := t.Bucket(bucketSubscriptionInfo); bucket != nil {
			if v := bucket.Get([]byte(name)); v != nil {
				userInfo = string(v)
			}
		}
		return nil
	})

	return
}
