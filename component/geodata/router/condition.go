package router

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/metacubex/mihomo/component/geodata/strmatcher"
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

type DomainMatcher struct {
	matchers strmatcher.IndexMatcher
	not      bool
}

func NewMphMatcherGroup(domains []*Domain, not bool) (*DomainMatcher, error) {
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
	return &DomainMatcher{
		matchers: g,
		not:      not,
	}, nil
}

// NewDomainMatcher new domain matcher.
func NewDomainMatcher(domains []*Domain, not bool) (*DomainMatcher, error) {
	g := new(strmatcher.MatcherGroup)
	for _, d := range domains {
		m, err := domainToMatcher(d)
		if err != nil {
			return nil, err
		}
		g.Add(m)
	}

	return &DomainMatcher{
		matchers: g,
		not:      not,
	}, nil
}

func (m *DomainMatcher) ApplyDomain(domain string) bool {
	isMatched := len(m.matchers.Match(strings.ToLower(domain))) > 0
	if m.not {
		isMatched = !isMatched
	}
	return isMatched
}

// CIDRList is an alias of []*CIDR to provide sort.Interface.
type CIDRList []*CIDR

// Len implements sort.Interface.
func (l *CIDRList) Len() int {
	return len(*l)
}

// Less implements sort.Interface.
func (l *CIDRList) Less(i int, j int) bool {
	ci := (*l)[i]
	cj := (*l)[j]

	if len(ci.Ip) < len(cj.Ip) {
		return true
	}

	if len(ci.Ip) > len(cj.Ip) {
		return false
	}

	for k := 0; k < len(ci.Ip); k++ {
		if ci.Ip[k] < cj.Ip[k] {
			return true
		}

		if ci.Ip[k] > cj.Ip[k] {
			return false
		}
	}

	return ci.Prefix < cj.Prefix
}

// Swap implements sort.Interface.
func (l *CIDRList) Swap(i int, j int) {
	(*l)[i], (*l)[j] = (*l)[j], (*l)[i]
}

type ipv6 struct {
	a uint64
	b uint64
}

type GeoIPMatcher struct {
	countryCode  string
	reverseMatch bool
	ip4          []uint32
	prefix4      []uint8
	ip6          []ipv6
	prefix6      []uint8
}

func normalize4(ip uint32, prefix uint8) uint32 {
	return (ip >> (32 - prefix)) << (32 - prefix)
}

func normalize6(ip ipv6, prefix uint8) ipv6 {
	if prefix <= 64 {
		ip.a = (ip.a >> (64 - prefix)) << (64 - prefix)
		ip.b = 0
	} else {
		ip.b = (ip.b >> (128 - prefix)) << (128 - prefix)
	}
	return ip
}

func (m *GeoIPMatcher) Init(cidrs []*CIDR) error {
	ip4Count := 0
	ip6Count := 0

	for _, cidr := range cidrs {
		ip := cidr.Ip
		switch len(ip) {
		case 4:
			ip4Count++
		case 16:
			ip6Count++
		default:
			return fmt.Errorf("unexpect ip length: %d", len(ip))
		}
	}

	cidrList := CIDRList(cidrs)
	sort.Sort(&cidrList)

	m.ip4 = make([]uint32, 0, ip4Count)
	m.prefix4 = make([]uint8, 0, ip4Count)
	m.ip6 = make([]ipv6, 0, ip6Count)
	m.prefix6 = make([]uint8, 0, ip6Count)

	for _, cidr := range cidrs {
		ip := cidr.Ip
		prefix := uint8(cidr.Prefix)
		switch len(ip) {
		case 4:
			m.ip4 = append(m.ip4, normalize4(binary.BigEndian.Uint32(ip), prefix))
			m.prefix4 = append(m.prefix4, prefix)
		case 16:
			ip6 := ipv6{
				a: binary.BigEndian.Uint64(ip[0:8]),
				b: binary.BigEndian.Uint64(ip[8:16]),
			}
			ip6 = normalize6(ip6, prefix)

			m.ip6 = append(m.ip6, ip6)
			m.prefix6 = append(m.prefix6, prefix)
		}
	}

	return nil
}

func (m *GeoIPMatcher) SetReverseMatch(isReverseMatch bool) {
	m.reverseMatch = isReverseMatch
}

func (m *GeoIPMatcher) match4(ip uint32) bool {
	if len(m.ip4) == 0 {
		return false
	}

	if ip < m.ip4[0] {
		return false
	}

	size := uint32(len(m.ip4))
	l := uint32(0)
	r := size
	for l < r {
		x := ((l + r) >> 1)
		if ip < m.ip4[x] {
			r = x
			continue
		}

		nip := normalize4(ip, m.prefix4[x])
		if nip == m.ip4[x] {
			return true
		}

		l = x + 1
	}

	return l > 0 && normalize4(ip, m.prefix4[l-1]) == m.ip4[l-1]
}

func less6(a ipv6, b ipv6) bool {
	return a.a < b.a || (a.a == b.a && a.b < b.b)
}

func (m *GeoIPMatcher) match6(ip ipv6) bool {
	if len(m.ip6) == 0 {
		return false
	}

	if less6(ip, m.ip6[0]) {
		return false
	}

	size := uint32(len(m.ip6))
	l := uint32(0)
	r := size
	for l < r {
		x := (l + r) / 2
		if less6(ip, m.ip6[x]) {
			r = x
			continue
		}

		if normalize6(ip, m.prefix6[x]) == m.ip6[x] {
			return true
		}

		l = x + 1
	}

	return l > 0 && normalize6(ip, m.prefix6[l-1]) == m.ip6[l-1]
}

// Match returns true if the given ip is included by the GeoIP.
func (m *GeoIPMatcher) Match(ip net.IP) bool {
	switch len(ip) {
	case 4:
		if m.reverseMatch {
			return !m.match4(binary.BigEndian.Uint32(ip))
		}
		return m.match4(binary.BigEndian.Uint32(ip))
	case 16:
		if m.reverseMatch {
			return !m.match6(ipv6{
				a: binary.BigEndian.Uint64(ip[0:8]),
				b: binary.BigEndian.Uint64(ip[8:16]),
			})
		}
		return m.match6(ipv6{
			a: binary.BigEndian.Uint64(ip[0:8]),
			b: binary.BigEndian.Uint64(ip[8:16]),
		})
	default:
		return false
	}
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

func (m *MultiGeoIPMatcher) ApplyIp(ip net.IP) bool {

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
