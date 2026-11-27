package provider

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// google cloud like document
var testGCloudJson = []byte(`{
  "syncToken": "123",
  "prefixes": [
    {
      "ipv4Prefix": "8.8.8.0/24",
      "scope": "us-east1"
    },
    {
      "ipv6Prefix": "2001:4860:4860::/64"
    },
    {
      "ipv4Prefix": null
    }
  ]
}`)

// github meta like document
var testGithubJson = []byte(`{
  "verifiable_password_authentication": true,
  "actions": ["192.30.252.0/22", "185.199.108.0/22"],
  "git": [
    "140.82.112.25/32",
    "140.82.114.25/32"
  ],
  "hooks": [],
  "pages": ["1.2.3.4"]
}`)

func TestParseJSONPath(t *testing.T) {
	segments, err := parseJSONPath("prefixes[].ipv4Prefix")
	require.NoError(t, err)
	assert.Equal(t, []jsonPathSegment{
		{key: "prefixes", iterate: true},
		{key: "ipv4Prefix"},
	}, segments)

	segments, err = parseJSONPath("$.actions[]")
	require.NoError(t, err)
	assert.Equal(t, []jsonPathSegment{
		{key: "actions", iterate: true},
	}, segments)

	segments, err = parseJSONPath("[]")
	require.NoError(t, err)
	assert.Equal(t, []jsonPathSegment{
		{key: "", iterate: true},
	}, segments)

	segments, err = parseJSONPath("a.b.c")
	require.NoError(t, err)
	assert.Equal(t, []jsonPathSegment{
		{key: "a"},
		{key: "b"},
		{key: "c"},
	}, segments)

	_, err = parseJSONPath("")
	assert.Error(t, err)

	_, err = parseJSONPath("a[0].b")
	assert.Error(t, err)
}

func TestRulesJSONParseIPCIDR(t *testing.T) {
	strategy := NewIPCidrStrategy()
	strategy.Reset()

	_, err := rulesJSONParse(testGCloudJson, strategy, []string{
		"prefixes[].ipv4Prefix",
		"prefixes[].ipv6Prefix",
	})
	require.NoError(t, err)
	assert.Equal(t, 2, strategy.Count())
}

func TestRulesJSONParseFlattenArrays(t *testing.T) {
	strategy := NewIPCidrStrategy()
	strategy.Reset()

	_, err := rulesJSONParse(testGithubJson, strategy, []string{
		"actions[]",
		"git[]",
	})
	require.NoError(t, err)
	assert.Equal(t, 4, strategy.Count())
}

func TestRulesJSONParseRootArray(t *testing.T) {
	buf := []byte(`["1.1.1.1/32", "8.8.8.8/32", null]`)
	strategy := NewIPCidrStrategy()
	strategy.Reset()

	_, err := rulesJSONParse(buf, strategy, []string{"[]"})
	require.NoError(t, err)
	assert.Equal(t, 2, strategy.Count())
}

func TestRulesJSONParseClassical(t *testing.T) {
	buf := []byte(`{"rules": ["DOMAIN-SUFFIX,google.com", "IP-CIDR,8.8.8.8/32"]}`)
	strategy := NewClassicalStrategy(func(tp, payload, target string, params []string, subRules map[string][]C.Rule) (C.Rule, error) {
		// a minimal fake rule is enough to verify insertion
		return &stubRule{tp: tp, payload: payload}, nil
	})

	_, err := rulesJSONParse(buf, strategy, []string{"rules[]"})
	require.NoError(t, err)
	assert.Equal(t, 2, strategy.Count())
}

type stubRule struct {
	tp      string
	payload string
}

func (r *stubRule) RuleType() C.RuleType { return C.DomainSuffix }

func (r *stubRule) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	return false, ""
}

func (r *stubRule) Adapter() string                { return "" }
func (r *stubRule) Payload() string                { return r.payload }
func (r *stubRule) ShouldFindProcess() bool        { return false }
func (r *stubRule) RuleNames() []string            { return nil }
func (r *stubRule) ProviderNames() []string        { return nil }
func (r *stubRule) ShouldResolveIP() bool          { return false }
func (r *stubRule) MatchDomain(domain string) bool { return false }
func (r *stubRule) MatchIp(ip netip.Addr) bool     { return false }

// stubTunnel implements P.Tunnel for tests (only callback parts are used).
type stubTunnel struct{}

func (stubTunnel) Providers() map[string]P.ProxyProvider    { return nil }
func (stubTunnel) RuleProviders() map[string]P.RuleProvider { return nil }
func (stubTunnel) RuleUpdateCallback() *utils.Callback[P.RuleProvider] {
	return utils.NewCallback[P.RuleProvider]()
}

func TestParseRuleProviderJSONFile(t *testing.T) {
	SetTunnel(stubTunnel{})

	dir := t.TempDir()
	defaultTestHomeDir := C.Path.HomeDir()
	C.SetHomeDir(dir)
	defer C.SetHomeDir(defaultTestHomeDir)

	path := filepath.Join(dir, "cloud.json")
	content := []byte(`{"prefixes":[{"ipv4Prefix":"8.8.8.0/24"},{"ipv6Prefix":"2001:4860:4860::/64"}]}`)
	require.NoError(t, os.WriteFile(path, content, 0o644))

	rp, err := ParseRuleProvider("gcloud", map[string]any{
		"type":     "file",
		"behavior": "ipcidr",
		"format":   "json",
		"path":     path,
		"json": map[string]any{
			"paths": []any{"prefixes[].ipv4Prefix", "prefixes[].ipv6Prefix"},
		},
	}, nil, func(string) resource.BundleFile { return nil })
	require.NoError(t, err)
	require.NotNil(t, rp)

	require.NoError(t, rp.Initial())
	assert.Equal(t, 2, rp.Count())

	metadata := &C.Metadata{DstIP: netip.MustParseAddr("8.8.8.8")}
	matched := rp.Match(metadata, C.RuleMatchHelper{})
	assert.True(t, matched)

	metadata = &C.Metadata{DstIP: netip.MustParseAddr("1.1.1.1")}
	matched = rp.Match(metadata, C.RuleMatchHelper{})
	assert.False(t, matched)
}

func TestParseRuleProviderJSONValidation(t *testing.T) {
	mk := func(extra map[string]any) map[string]any {
		mapping := map[string]any{
			"type":     "file",
			"behavior": "ipcidr",
			"path":     "rules.json",
		}
		for k, v := range extra {
			mapping[k] = v
		}
		return mapping
	}

	// format json without json.paths must fail
	_, err := ParseRuleProvider("bad1", mk(map[string]any{"format": "json"}), nil, func(string) resource.BundleFile { return nil })
	assert.ErrorContains(t, err, "json.paths")

	// json block with yaml format must fail
	_, err = ParseRuleProvider("bad2", mk(map[string]any{
		"json": map[string]any{"paths": []any{"prefixes[].ipv4Prefix"}},
	}), nil, func(string) resource.BundleFile { return nil })
	assert.ErrorContains(t, err, "json")

	// empty paths block is tolerated for non-json formats
	rp, err := ParseRuleProvider("ok", mk(map[string]any{
		"json": map[string]any{},
	}), nil, func(string) resource.BundleFile { return nil })
	require.NoError(t, err)
	assert.NotNil(t, rp)
}
