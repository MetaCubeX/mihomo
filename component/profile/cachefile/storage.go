package cachefile

import (
	"sort"
	"time"

	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/bbolt"
	"github.com/vmihailenco/msgpack/v5"
)

const storageSizeLimit = 1024 * 1024
const storageKeySizeLimit = 64
const maxStorageEntries = storageSizeLimit / storageKeySizeLimit

type StorageData struct {
	Data []byte
	Time time.Time
}

func decodeStorageData(v []byte) (StorageData, error) {
	var storage StorageData
	if err := msgpack.Unmarshal(v, &storage); err != nil {
		return StorageData{}, err
	}
	return storage, nil
}

func (c *CacheFile) GetStorage(key string) []byte {
	if c.DB == nil {
		return nil
	}
	var data []byte
	decodeFailed := false
	err := c.DB.View(func(t *bbolt.Tx) error {
		if bucket := t.Bucket(bucketStorage); bucket != nil {
			if v := bucket.Get([]byte(key)); v != nil {
				storage, err := decodeStorageData(v)
				if err != nil {
					decodeFailed = true
					return err
				}
				data = storage.Data
			}
		}
		return nil
	})
	if err != nil {
		log.Warnln("[CacheFile] read cache for key %s failed: %s", key, err.Error())
		if decodeFailed {
			c.DeleteStorage(key)
		}
		return nil
	}
	return data
}

func (c *CacheFile) SetStorage(key string, data []byte) {
	if c.DB == nil {
		return
	}
	if len(key) > storageKeySizeLimit {
		log.Warnln("[CacheFile] skip storage for key %s: key exceeds %d bytes", key, storageKeySizeLimit)
		return
	}
	if len(data) > storageSizeLimit {
		log.Warnln("[CacheFile] skip storage for key %s: payload exceeds %d bytes", key, storageSizeLimit)
		return
	}
	keyBytes := []byte(key)
	payload, err := msgpack.Marshal(StorageData{
		Data: data,
		Time: time.Now(),
	})
	if err != nil {
		return
	}
	err = c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketStorage)
		if err != nil {
			return err
		}
		type storageEntry struct {
			Key  string
			Data StorageData
		}

		entries := make(map[string]StorageData)
		usedSize := 0
		entryCount := 0
		corruptedKeys := make([][]byte, 0)
		c := bucket.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			storage, err := decodeStorageData(v)
			if err != nil {
				log.Warnln("[CacheFile] drop corrupted storage entry %s: %s", string(k), err.Error())
				corruptedKeys = append(corruptedKeys, append([]byte(nil), k...))
				continue
			}
			entryKey := string(k)
			entries[entryKey] = storage
			if entryKey != key {
				usedSize += len(storage.Data)
				entryCount++
			}
		}
		for _, k := range corruptedKeys {
			if err := bucket.Delete(k); err != nil {
				return err
			}
		}

		evictionQueue := make([]storageEntry, 0, len(entries))
		for entryKey, storage := range entries {
			if entryKey == key {
				continue
			}
			evictionQueue = append(evictionQueue, storageEntry{
				Key:  entryKey,
				Data: storage,
			})
		}
		sort.Slice(evictionQueue, func(i, j int) bool {
			left := evictionQueue[i]
			right := evictionQueue[j]
			if left.Data.Time.Equal(right.Data.Time) {
				return left.Key < right.Key
			}
			return left.Data.Time.Before(right.Data.Time)
		})

		for _, entry := range evictionQueue {
			if usedSize+len(data) <= storageSizeLimit && entryCount < maxStorageEntries {
				break
			}
			if err := bucket.Delete([]byte(entry.Key)); err != nil {
				return err
			}
			log.Infoln("[CacheFile] evict storage entry %s to make room for %s", entry.Key, key)
			usedSize -= len(entry.Data.Data)
			entryCount--
		}
		return bucket.Put(keyBytes, payload)
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
	}
}

func (c *CacheFile) DeleteStorage(key string) {
	if c.DB == nil {
		return
	}
	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket := t.Bucket(bucketStorage)
		if bucket == nil {
			return nil
		}
		return bucket.Delete([]byte(key))
	})
	if err != nil {
		log.Warnln("[CacheFile] delete cache from %s failed: %s", c.DB.Path(), err.Error())
	}
}
