package router

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/component/cidr"
	"github.com/metacubex/mihomo/component/geodata/strmatcher"
	"github.com/metacubex/mihomo/component/trie"
)

var matcherTypeMap = map[Domain_Type]strmatcher.Type{
	Domain_Plain:  strmatcher.Substr,
	Domain_Regex:  strmatcher.Regex,
	Domain_Domain: strmatcher.Domain,
	Domain_Full:   strmatcher.Full,
}

func domainToMatcher(domain *Domain) (strmatcher.Matcher, error) {
	matcherType, f := matcherTypeMap[domain.Type]
	if !f {
		return nil, fmt.Errorf("unsupported domain type %v", domain.Type)
	}

	matcher, err := matcherType.New(domain.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to create domain matcher, base error: %s", err.Error())
	}

	return matcher, nil
}

type DomainMatcher interface {
	ApplyDomain(string) bool
	Count() int
}

type succinctDomainMatcher struct {
	set           *trie.DomainSet
	otherMatchers []strmatcher.Matcher
	count         int
}

func (m *succinctDomainMatcher) ApplyDomain(domain string) bool {
	isMatched := m.set.Has(domain)
	if !isMatched {
		for _, matcher := range m.otherMatchers {
			isMatched = matcher.Match(domain)
			if isMatched {
				break
			}
		}
	}
	return isMatched
}

func (m *succinctDomainMatcher) Count() int {
	return m.count
}

func NewSuccinctMatcherGroup(domains []*Domain) (DomainMatcher, error) {
	t := trie.New[struct{}]()
	m := &succinctDomainMatcher{
		count: len(domains),
	}
	for _, d := range domains {
		switch d.Type {
		case Domain_Plain, Domain_Regex:
			matcher, err := matcherTypeMap[d.Type].New(d.Value)
			if err != nil {
				return nil, err
			}
			m.otherMatchers = append(m.otherMatchers, matcher)

		case Domain_Domain:
			err := t.Insert("+."+d.Value, struct{}{})
			if err != nil {
				return nil, err
			}

		case Domain_Full:
			err := t.Insert(d.Value, struct{}{})
			if err != nil {
				return nil, err
			}
		}
	}
	m.set = t.NewDomainSet()
	return m, nil
}

type v2rayDomainMatcher struct {
	matchers strmatcher.IndexMatcher
	count    int
}

func NewMphMatcherGroup(domains []*Domain) (DomainMatcher, error) {
	g := strmatcher.NewMphMatcherGroup()
	for _, d := range domains {
		matcherType, f := matcherTypeMap[d.Type]
		if !f {
			return nil, fmt.Errorf("unsupported domain type %v", d.Type)
		}
		_, err := g.AddPattern(d.Value, matcherType)
		if err != nil {
			return nil, err
		}
	}
	g.Build()
	return &v2rayDomainMatcher{
		matchers: g,
		count:    len(domains),
	}, nil
}

func (m *v2rayDomainMatcher) ApplyDomain(domain string) bool {
	return len(m.matchers.Match(strings.ToLower(domain))) > 0
}

func (m *v2rayDomainMatcher) Count() int {
	return m.count
}

type notDomainMatcher struct {
	DomainMatcher
}

func (m notDomainMatcher) ApplyDomain(domain string) bool {
	return !m.DomainMatcher.ApplyDomain(domain)
}

func NewNotDomainMatcherGroup(matcher DomainMatcher) DomainMatcher {
	return notDomainMatcher{matcher}
}

type IPMatcher interface {
	Match(ip netip.Addr) bool
	Count() int
}

type geoIPMatcher struct {
	cidrSet *cidr.IpCidrSet
	count   int
}

// Match returns true if the given ip is included by the GeoIP.
func (m *geoIPMatcher) Match(ip netip.Addr) bool {
	return m.cidrSet.IsContain(ip)
}

func (m *geoIPMatcher) Count() int {
	return m.count
}

func NewGeoIPMatcher(cidrList []*CIDR) (IPMatcher, error) {
	m := &geoIPMatcher{
		cidrSet: cidr.NewIpCidrSet(),
		count:   len(cidrList),
	}
	for _, cidr := range cidrList {
		addr, ok := netip.AddrFromSlice(cidr.Ip)
		if !ok {
			return nil, fmt.Errorf("error when loading GeoIP: invalid IP: %s", cidr.Ip)
		}
		err := m.cidrSet.AddIpCidr(netip.PrefixFrom(addr, int(cidr.Prefix)))
		if err != nil {
			return nil, fmt.Errorf("error when loading GeoIP: %w", err)
		}
	}
	err := m.cidrSet.Merge()
	if err != nil {
		return nil, err
	}

	return m, nil
}

type notIPMatcher struct {
	IPMatcher
}

func (m notIPMatcher) Match(ip netip.Addr) bool {
	return !m.IPMatcher.Match(ip)
}

func NewNotIpMatcherGroup(matcher IPMatcher) IPMatcher {
	return notIPMatcher{matcher}
}
