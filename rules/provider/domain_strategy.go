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
	count            int
	domainSetBuilder trie.DomainSetBuilder
	domainSet        *trie.DomainSet
}

func (d *domainStrategy) Behavior() P.RuleBehavior {
	return P.Domain
}

func (d *domainStrategy) Match(metadata *C.Metadata, helper C.RuleMatchHelper) bool {
	domain := strings.ToLower(metadata.RuleHost())
	return d.domainSet != nil && d.domainSet.Has(domain)
}

func (d *domainStrategy) Count() int {
	return d.count
}

func (d *domainStrategy) Reset() {
	d.domainSetBuilder.Reset()
	d.domainSet = nil
	d.count = 0
}

func (d *domainStrategy) Insert(rule string) {
	if strings.ContainsRune(rule, '/') {
		log.Warnln("skip invalid domain from rule provider: invalid domain %q: slash is not allowed", rule)
		return
	}
	err := d.domainSetBuilder.Insert(rule)
	if err != nil {
		log.Warnln("skip invalid domain from rule provider: %s", err)
	} else {
		d.count++
	}
}

func (d *domainStrategy) FinishInsert() {
	d.domainSet = d.domainSetBuilder.Build()
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

// DumpMrs emits a compact domain rule list in lexicographical order through f.
// A "domain" entry and a ".domain" entry are represented by one "+.domain" rule;
// either entry alone is emitted unchanged. Returning false from f stops iteration.
func (d *domainStrategy) DumpMrs(f func(key string) bool) {
	if d.domainSet != nil {
		var keys []string
		d.domainSet.Foreach(func(key string) bool {
			keys = append(keys, key)
			return true
		})

		// Group exact and suffix-only entries for the same domain.
		// Set entries are unique, so each group contains at most two entries.
		slices.SortFunc(keys, func(left, right string) int {
			left = strings.TrimPrefix(left, ".")
			right = strings.TrimPrefix(right, ".")
			return strings.Compare(left, right)
		})
		for index := 0; index+1 < len(keys); index++ {
			domain := strings.TrimPrefix(keys[index], ".")
			if domain == strings.TrimPrefix(keys[index+1], ".") {
				// Both the domain itself and its subdomains are covered by one "+." rule.
				keys[index] = "+." + domain
				keys[index+1] = ""
				index++
			}
		}
		keys = slices.DeleteFunc(keys, func(key string) bool { return key == "" })
		// Sort the compact rules by their full text, including wildcard prefixes.
		slices.Sort(keys)

		for _, key := range keys {
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
