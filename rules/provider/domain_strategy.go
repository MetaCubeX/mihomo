package provider

import (
	"errors"
	"io"

	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type domainStrategy struct {
	count      int
	domainTrie *trie.DomainTrie[struct{}]
	domainSet  *trie.DomainSet
}

func (d *domainStrategy) ShouldFindProcess() bool {
	return false
}

func (d *domainStrategy) Match(metadata *C.Metadata) bool {
	return d.domainSet != nil && d.domainSet.Has(metadata.RuleHost())
}

func (d *domainStrategy) Count() int {
	return d.count
}

func (d *domainStrategy) ShouldResolveIP() bool {
	return false
}

func (d *domainStrategy) Reset() {
	d.domainTrie = trie.New[struct{}]()
	d.domainSet = nil
	d.count = 0
}

func (d *domainStrategy) Insert(rule string) {
	err := d.domainTrie.Insert(rule, struct{}{})
	if err != nil {
		log.Warnln("invalid domain:[%s]", rule)
	} else {
		d.count++
	}
}

func (d *domainStrategy) FinishInsert() {
	d.domainSet = d.domainTrie.NewDomainSet()
	d.domainTrie = nil
}

func (d *domainStrategy) FromMrs(r io.Reader) error {
	domainSet, count, err := trie.ReadDomainSetBin(r)
	if err != nil {
		return err
	}
	d.count = int(count)
	d.domainSet = domainSet
	return nil
}

func (d *domainStrategy) WriteMrs(w io.Writer) error {
	if d.domainSet == nil {
		return errors.New("nil domainSet")
	}
	return d.domainSet.WriteBin(w, int64(d.count))
}

var _ mrsRuleStrategy = (*domainStrategy)(nil)

func NewDomainStrategy() *domainStrategy {
	return &domainStrategy{}
}
