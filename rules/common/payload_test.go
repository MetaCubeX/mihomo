package common

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
)

func TestParseSlashSeparatedPayload(t *testing.T) {
	t.Parallel()

	values, err := parseSlashSeparatedPayload(" CN / us ", "country", strings.ToLower)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{"cn", "us"}
	if !reflect.DeepEqual(values, expected) {
		t.Fatalf("unexpected parsed values: got %v, want %v", values, expected)
	}
}

func TestParseSlashSeparatedPayloadDeduplicatesPreservingOrder(t *testing.T) {
	t.Parallel()

	values, err := parseSlashSeparatedPayload(" CN / us / cn / jp / us ", "country", strings.ToLower)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{"cn", "us", "jp"}
	if !reflect.DeepEqual(values, expected) {
		t.Fatalf("unexpected parsed values: got %v, want %v", values, expected)
	}
}

func TestParseSlashSeparatedPayloadRejectsEmptyPart(t *testing.T) {
	t.Parallel()

	testCases := []string{"cn//us", " / cn", "cn / "}
	for _, input := range testCases {
		if _, err := parseSlashSeparatedPayload(input, "country", nil); err == nil {
			t.Fatalf("expected error for empty slash-separated part in %q", input)
		}
	}
}

func TestNewGEOIPRejectsEmptySlashPayloadBeforeGeodata(t *testing.T) {
	t.Parallel()

	if _, err := NewGEOIP("lan/", "DIRECT", false, true); err == nil {
		t.Fatalf("expected error for empty slash-separated geoip payload")
	}
}

func TestNewGEOIPLanPayloadCanonicalizesWithoutGeodata(t *testing.T) {
	t.Parallel()

	rule, err := NewGEOIP(" LAN / lan ", "DIRECT", false, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := rule.Payload(), "lan"; got != want {
		t.Fatalf("unexpected payload: got %q, want %q", got, want)
	}
}

func TestGEOSITEPayloadCanonicalization(t *testing.T) {
	t.Parallel()

	countries, err := parseSlashSeparatedPayload("CN / gfw / cn", "geosite country", strings.ToLower)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	rule := &GEOSITE{countries: countries, payload: strings.Join(countries, "/")}
	if got, want := rule.Payload(), "cn/gfw"; got != want {
		t.Fatalf("unexpected payload: got %q, want %q", got, want)
	}
}

func TestIPASNPayloadCanonicalization(t *testing.T) {
	t.Parallel()

	asns, err := parseSlashSeparatedPayload("123 / 456 / 123", "asn", nil)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	rule := &ASN{asns: asns, payload: strings.Join(asns, "/")}
	if got, want := rule.Payload(), "123/456"; got != want {
		t.Fatalf("unexpected payload: got %q, want %q", got, want)
	}
}

func TestGEOIPMixedPayloadCanonicalizes(t *testing.T) {
	t.Parallel()

	countries, err := parseSlashSeparatedPayload(" LAN / cn / lan ", "geoip country", strings.ToLower)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	rule := &GEOIP{countries: countries, payload: strings.Join(countries, "/")}
	if got, want := rule.Payload(), "lan/cn"; got != want {
		t.Fatalf("unexpected payload: got %q, want %q", got, want)
	}
}

func TestGEOIPGetCountryReturnsFirstCountry(t *testing.T) {
	t.Parallel()

	rule := &GEOIP{countries: []string{"cn", "us"}, payload: "cn/us"}
	if got, want := rule.GetCountry(), "cn"; got != want {
		t.Fatalf("unexpected country: got %q, want %q", got, want)
	}
}

func TestGEOIPGetCountriesReturnsCopy(t *testing.T) {
	t.Parallel()

	rule := &GEOIP{countries: []string{"cn", "us"}, payload: "cn/us"}
	countries := rule.GetCountries()
	countries[0] = "jp"
	if got, want := rule.GetCountries()[0], "cn"; got != want {
		t.Fatalf("unexpected country mutation: got %q, want %q", got, want)
	}
}

func TestASNGetASNReturnsFirstASN(t *testing.T) {
	t.Parallel()

	rule := &ASN{asns: []string{"13335", "396982"}, payload: "13335/396982"}
	if got, want := rule.GetASN(), "13335"; got != want {
		t.Fatalf("unexpected asn: got %q, want %q", got, want)
	}
}

func TestASNGetASNsReturnsCopy(t *testing.T) {
	t.Parallel()

	rule := &ASN{asns: []string{"13335", "396982"}, payload: "13335/396982"}
	asns := rule.GetASNs()
	asns[0] = "1"
	if got, want := rule.GetASNs()[0], "13335"; got != want {
		t.Fatalf("unexpected asn mutation: got %q, want %q", got, want)
	}
}

func TestNewGEOIPPureLanHasZeroRecordSize(t *testing.T) {
	t.Parallel()

	rule, err := NewGEOIP("lan", "DIRECT", false, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := rule.GetRecodeSize(); got != 0 {
		t.Fatalf("unexpected record size: got %d, want 0", got)
	}
}

func TestGeoIPPureLanDoesNotMatchPublicIP(t *testing.T) {
	t.Parallel()

	rule := &GEOIP{countries: []string{"lan"}}
	if rule.MatchIp(netip.MustParseAddr("8.8.8.8")) {
		t.Fatalf("unexpected match for public address with pure lan geoip rule")
	}
}

func TestGeoIPReturnsAdapterOnLanMiss(t *testing.T) {
	t.Parallel()

	rule := &GEOIP{countries: []string{"lan"}, adapter: "DIRECT"}
	matched, adapter := rule.Match(&C.Metadata{DstIP: netip.MustParseAddr("8.8.8.8")}, C.RuleMatchHelper{})
	if matched {
		t.Fatalf("unexpected match for public address with pure lan geoip rule")
	}
	if adapter != "DIRECT" {
		t.Fatalf("unexpected adapter: got %q, want %q", adapter, "DIRECT")
	}
}

func TestGeoIPMatchLanMixedPayload(t *testing.T) {
	t.Parallel()

	rule := &GEOIP{countries: []string{"lan", "cn"}}
	if !rule.MatchIp(netip.MustParseAddr("192.168.1.1")) {
		t.Fatalf("expected lan address to match mixed geoip rule")
	}
}

func TestGeoIPGetCombinedIPMatcherIncludesLan(t *testing.T) {
	oldGeodataMode := geodata.GeodataMode()
	geodata.SetGeodataMode(true)
	t.Cleanup(func() {
		geodata.SetGeodataMode(oldGeodataMode)
	})

	rule := &GEOIP{countries: []string{"lan"}}
	matcher, err := rule.GetIPMatcher()
	if err != nil {
		t.Fatalf("unexpected matcher error: %v", err)
	}
	if !matcher.Match(netip.MustParseAddr("192.168.1.1")) {
		t.Fatalf("expected exported geoip matcher to include lan addresses")
	}
	if matcher.Match(netip.MustParseAddr("8.8.8.8")) {
		t.Fatalf("unexpected public address match with lan-only matcher")
	}
	if got := matcher.Count(); got != 0 {
		t.Fatalf("unexpected lan matcher count: got %d, want 0", got)
	}
}

func TestMultiGeoIPMatcherMatchesAnyAndCountsAllRecords(t *testing.T) {
	t.Parallel()

	matchers := []router.IPMatcher{
		staticIPMatcher{
			ips:   map[netip.Addr]bool{netip.MustParseAddr("8.8.8.8"): true},
			count: 1,
		},
		staticIPMatcher{
			ips:   map[netip.Addr]bool{netip.MustParseAddr("223.5.5.5"): true},
			count: 1,
		},
	}
	matcher, err := newMultiGeoIPMatcher(matchers)
	if err != nil {
		t.Fatalf("unexpected matcher error: %v", err)
	}
	if !matcher.Match(netip.MustParseAddr("223.5.5.5")) {
		t.Fatalf("expected combined geoip matcher to match")
	}
	if !matcher.Match(netip.MustParseAddr("8.8.8.8")) {
		t.Fatalf("expected combined geoip matcher to match")
	}
	if got, want := matcher.Count(), 2; got != want {
		t.Fatalf("unexpected matcher count: got %d, want %d", got, want)
	}
}

func TestGeoIPLoadNamedIPMatchersFailsOnAnyInvalidPayload(t *testing.T) {
	oldGeodataMode := geodata.GeodataMode()
	geodata.SetGeodataMode(true)
	t.Cleanup(func() {
		geodata.SetGeodataMode(oldGeodataMode)
	})

	rule := &GEOIP{countries: []string{"lan", ""}}
	if _, err := rule.loadNamedIPMatchers(); err == nil {
		t.Fatalf("expected error when any non-lan matcher cannot load")
	}
}

func TestGEOIPMatchUsesCachedMetadataOnMiss(t *testing.T) {
	t.Parallel()

	rule := &GEOIP{countries: []string{"us"}, adapter: "DIRECT"}
	metadata := &C.Metadata{
		DstIP:    netip.MustParseAddr("8.8.8.8"),
		DstGeoIP: []string{"cn"},
	}

	matched, adapter := rule.Match(metadata, C.RuleMatchHelper{})
	if matched {
		t.Fatalf("expected cached geoip metadata miss")
	}
	if adapter != "DIRECT" {
		t.Fatalf("unexpected adapter: got %q, want %q", adapter, "DIRECT")
	}
}

func TestGeoIPDnsFallbackFilterPreservesLanBypass(t *testing.T) {
	t.Parallel()

	filter := dnsFallbackFilter{GEOIP: &GEOIP{countries: []string{"lan", "cn"}}}
	if filter.MatchIp(netip.MustParseAddr("10.0.0.1")) {
		t.Fatalf("expected lan address to bypass fallback filter")
	}
}

func TestGeoIPDnsFallbackFilterDoesNotFallbackOnMatcherError(t *testing.T) {
	oldGeodataMode := geodata.GeodataMode()
	geodata.SetGeodataMode(true)
	t.Cleanup(func() {
		geodata.SetGeodataMode(oldGeodataMode)
	})

	filter := dnsFallbackFilter{GEOIP: &GEOIP{countries: []string{""}}}
	if filter.MatchIp(netip.MustParseAddr("8.8.8.8")) {
		t.Fatalf("expected matcher error to bypass fallback filter")
	}
}

func TestMultiGeoSiteMatcherMatchesAnyAndCountsAllRecords(t *testing.T) {
	t.Parallel()

	matcher := multiGeoSiteMatcher{
		staticDomainMatcher{domains: map[string]bool{"google.com": true}, count: 1},
		staticDomainMatcher{domains: map[string]bool{"youtube.com": true}, count: 1},
	}

	if !matcher.ApplyDomain("youtube.com") {
		t.Fatalf("expected combined geosite matcher to match")
	}
	if got, want := matcher.Count(), 2; got != want {
		t.Fatalf("unexpected matcher count: got %d, want %d", got, want)
	}
}

func TestGeoSiteLoadDomainMatcherFailsOnAnyInvalidPayload(t *testing.T) {
	t.Parallel()

	rule := &GEOSITE{
		countries: []string{"", "still-missing"},
		payload:   "/still-missing",
	}
	if _, err := rule.loadDomainMatcher(); err == nil {
		t.Fatalf("expected error when any geosite matcher cannot load")
	}
}

type staticIPMatcher struct {
	ips   map[netip.Addr]bool
	count int
}

func (m staticIPMatcher) Match(ip netip.Addr) bool {
	return m.ips[ip]
}

func (m staticIPMatcher) Count() int {
	return m.count
}

type staticDomainMatcher struct {
	domains map[string]bool
	count   int
}

func (m staticDomainMatcher) ApplyDomain(domain string) bool {
	return m.domains[domain]
}

func (m staticDomainMatcher) Count() int {
	return m.count
}
