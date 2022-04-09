package cert

import (
	"crypto/tls"

	"github.com/Dreamacro/clash/component/trie"
)

// DomainTrieCertsStorage cache wildcard certificates
type DomainTrieCertsStorage struct {
	certsCache *trie.DomainTrie[*tls.Certificate]
}

// Get gets the certificate from the storage
func (c *DomainTrieCertsStorage) Get(key string) (*tls.Certificate, bool) {
	ca := c.certsCache.Search(key)
	if ca == nil {
		return nil, false
	}
	return ca.Data(), true
}

// Set saves the certificate to the storage
func (c *DomainTrieCertsStorage) Set(key string, cert *tls.Certificate) {
	_ = c.certsCache.Insert(key, cert)
}

func NewDomainTrieCertsStorage() *DomainTrieCertsStorage {
	return &DomainTrieCertsStorage{
		certsCache: trie.New[*tls.Certificate](),
	}
}
