package cert

import (
	"crypto/tls"
	"time"

	"github.com/Dreamacro/clash/common/cache"
)

var TTL = time.Hour * 2

// AutoGCCertsStorage cache with the generated certificates, auto released after TTL
type AutoGCCertsStorage struct {
	certsCache *cache.Cache[string, *tls.Certificate]
}

// Get gets the certificate from the storage
func (c *AutoGCCertsStorage) Get(key string) (*tls.Certificate, bool) {
	ca := c.certsCache.Get(key)
	return ca, ca != nil
}

// Set saves the certificate to the storage
func (c *AutoGCCertsStorage) Set(key string, cert *tls.Certificate) {
	c.certsCache.Put(key, cert, TTL)
}

func NewAutoGCCertsStorage() *AutoGCCertsStorage {
	return &AutoGCCertsStorage{
		certsCache: cache.New[string, *tls.Certificate](TTL),
	}
}
