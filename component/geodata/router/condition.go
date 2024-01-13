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
}

type succinctDomainMatcher struct {
	set           *trie.DomainSet
	otherMatchers []strmatcher.Matcher
	not           bool
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
	if m.not {
		isMatched = !isMatched
	}
	return isMatched
}

func NewSuccinctMatcherGroup(domains []*Domain, not bool) (DomainMatcher, error) {
	t := trie.New[struct{}]()
	m := &succinctDomainMatcher{
		not: not,
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
	not      bool
}

func NewMphMatcherGroup(domains []*Domain, not bool) (DomainMatcher, error) {
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
		not:      not,
	}, nil
}

func (m *v2rayDomainMatcher) ApplyDomain(domain string) bool {
	isMatched := len(m.matchers.Match(strings.ToLower(domain))) > 0
	if m.not {
		isMatched = !isMatched
	}
	return isMatched
}

type GeoIPMatcher struct {
	countryCode  string
	reverseMatch bool
	cidrSet      *cidr.IpCidrSet
}

func (m *GeoIPMatcher) Init(cidrs []*CIDR) error {
	for _, cidr := range cidrs {
		addr, ok := netip.AddrFromSlice(cidr.Ip)
		if !ok {
			return fmt.Errorf("error when loading GeoIP: invalid IP: %s", cidr.Ip)
		}
		err := m.cidrSet.AddIpCidr(netip.PrefixFrom(addr, int(cidr.Prefix)))
		if err != nil {
			return fmt.Errorf("error when loading GeoIP: %w", err)
		}
	}
	return m.cidrSet.Merge()
}

func (m *GeoIPMatcher) SetReverseMatch(isReverseMatch bool) {
	m.reverseMatch = isReverseMatch
}

// Match returns true if the given ip is included by the GeoIP.
func (m *GeoIPMatcher) Match(ip netip.Addr) bool {
	match := m.cidrSet.IsContain(ip)
	if m.reverseMatch {
		return !match
	}
	return match
}

// GeoIPMatcherContainer is a container for GeoIPMatchers. It keeps unique copies of GeoIPMatcher by country code.
type GeoIPMatcherContainer struct {
	matchers []*GeoIPMatcher
}

// Add adds a new GeoIP set into the container.
// If the country code of GeoIP is not empty, GeoIPMatcherContainer will try to find an existing one, instead of adding a new one.
func (c *GeoIPMatcherContainer) Add(geoip *GeoIP) (*GeoIPMatcher, error) {
	if len(geoip.CountryCode) > 0 {
		for _, m := range c.matchers {
			if m.countryCode == geoip.CountryCode && m.reverseMatch == geoip.ReverseMatch {
				return m, nil
			}
		}
	}

	m := &GeoIPMatcher{
		countryCode:  geoip.CountryCode,
		reverseMatch: geoip.ReverseMatch,
		cidrSet:      cidr.NewIpCidrSet(),
	}
	if err := m.Init(geoip.Cidr); err != nil {
		return nil, err
	}
	if len(geoip.CountryCode) > 0 {
		c.matchers = append(c.matchers, m)
	}
	return m, nil
}

var globalGeoIPContainer GeoIPMatcherContainer

type MultiGeoIPMatcher struct {
	matchers []*GeoIPMatcher
}

func NewGeoIPMatcher(geoip *GeoIP) (*GeoIPMatcher, error) {
	matcher, err := globalGeoIPContainer.Add(geoip)
	if err != nil {
		return nil, err
	}

	return matcher, nil
}

func (m *MultiGeoIPMatcher) ApplyIp(ip netip.Addr) bool {
	for _, matcher := range m.matchers {
		if matcher.Match(ip) {
			return true
		}
	}

	return false
}

func NewMultiGeoIPMatcher(geoips []*GeoIP) (*MultiGeoIPMatcher, error) {
	var matchers []*GeoIPMatcher
	for _, geoip := range geoips {
		matcher, err := globalGeoIPContainer.Add(geoip)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, matcher)
	}

	matcher := &MultiGeoIPMatcher{
		matchers: matchers,
	}

	return matcher, nil
}
