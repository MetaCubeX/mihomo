package provider

import (
	"errors"
	"io"
	"strings"

	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"

	"golang.org/x/exp/slices"
)

type domainStrategy struct {
	count      int
	domainTrie *trie.DomainTrie[struct{}]
	domainSet  *trie.DomainSet
}

func (d *domainStrategy) Behavior() P.RuleBehavior {
	return P.Domain
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
	if strings.ContainsRune(rule, '/') {
		log.Warnln("invalid domain:[%s]", rule)
		return
	}
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

func (d *domainStrategy) FromMrs(r io.Reader, count int) error {
	domainSet, err := trie.ReadDomainSetBin(r)
	if err != nil {
		return err
	}
	d.count = count
	d.domainSet = domainSet
	return nil
}

func (d *domainStrategy) WriteMrs(w io.Writer) error {
	if d.domainSet == nil {
		return errors.New("nil domainSet")
	}
	return d.domainSet.WriteBin(w)
}

func (d *domainStrategy) DumpMrs(f func(key string) bool) {
	if d.domainSet != nil {
		var keys []string
		d.domainSet.Foreach(func(key string) bool {
			keys = append(keys, key)
			return true
		})
		slices.Sort(keys)

		for _, key := range keys {
			if _, ok := slices.BinarySearch(keys, "+."+key); ok {
				continue // ignore the rules added by trie internal processing
			}
			if !f(key) {
				return
			}
		}
	}
}

var _ mrsRuleStrategy = (*domainStrategy)(nil)

func NewDomainStrategy() *domainStrategy {
	return &domainStrategy{}
}
