package networkpolicy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalize_Interfaces(t *testing.T) {
	c := &NetworkContext{
		Version: 1,
		Interfaces: []InterfaceContext{
			{
				Name:       "wlan0",
				IfaceType:  "WIFI",
				BSSID:      "AA-BB-CC-DD-EE-FF",
				GatewayIP:  "2001:DB8:0::1",
				GatewayMAC: "aabbccddeeff",
				Subnets:    []string{"192.168.1.0/24", "10.0.0.0/8", "192.168.1.0/24", ""},
			},
			{
				Name:      "en0", // out-of-order: normalize should sort to front
				IfaceType: "ethernet",
			},
		},
		DNSSuffix: []string{"CORP.Example.COM", "", "home.example.com", "CORP.Example.COM"},
	}
	c.normalize()

	assert.Equal(t, 1, c.Version, "version passes through unchanged")
	// Sorted by name: en0 < wlan0
	assert.Equal(t, "en0", c.Interfaces[0].Name)
	assert.Equal(t, "wlan0", c.Interfaces[1].Name)

	// wlan0 (now index 1) normalized
	w := &c.Interfaces[1]
	assert.Equal(t, "wifi", w.IfaceType)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", w.BSSID)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", w.GatewayMAC)
	assert.Equal(t, "2001:db8::1", w.GatewayIP)
	assert.True(t, w.gatewayIPParsed.IsValid())
	assert.Equal(t, []string{"10.0.0.0/8", "192.168.1.0/24"}, w.Subnets, "sorted, deduped, empty filtered")

	// DNSSuffix normalized: lowercased, empty filtered, sorted, deduped
	assert.Equal(t, []string{"corp.example.com", "home.example.com"}, c.DNSSuffix)
}

func TestNormalize_Idempotent(t *testing.T) {
	c := &NetworkContext{
		Version: 1,
		Interfaces: []InterfaceContext{
			{Name: "wlan0", BSSID: "aa:bb:cc:dd:ee:ff", Subnets: []string{"10.0.0.0/8"}},
		},
		DNSSuffix: []string{"corp"},
	}
	c.normalize()
	snapshot := *c
	c.normalize()
	assert.Equal(t, snapshot.Interfaces[0].BSSID, c.Interfaces[0].BSSID)
	assert.Equal(t, snapshot.Interfaces[0].Subnets, c.Interfaces[0].Subnets)
	assert.Equal(t, snapshot.DNSSuffix, c.DNSSuffix)
}

func TestNormalize_ClearsStaleDerived(t *testing.T) {
	// Reused struct must not leak derived state when the sampler edits raw fields.
	c := &NetworkContext{
		Interfaces: []InterfaceContext{
			{Name: "wlan0", Subnets: []string{"10.0.0.0/8"}, GatewayIP: "10.0.0.1"},
		},
	}
	c.normalize()
	assert.NotEmpty(t, c.Interfaces[0].subnetsParsed)
	assert.True(t, c.Interfaces[0].gatewayIPParsed.IsValid())

	c.Interfaces[0].Subnets = []string{"not-a-cidr"}
	c.normalize()
	assert.NotNil(t, c.normalizeErr)
	// iface.normalize() resets both derived fields at the top, then processes
	// GatewayIP (success) and Subnets (failure, returns). Final state:
	// gatewayIPParsed valid, subnetsParsed nil. This test pins the field
	// processing order; flipping it without updating here would regress.
	assert.True(t, c.Interfaces[0].gatewayIPParsed.IsValid(), "GatewayIP normalize ran before Subnets")
	assert.Nil(t, c.Interfaces[0].subnetsParsed, "Subnets parse failed, derived slice stays nil")
}

func TestNormalize_IPv6StripsZone(t *testing.T) {
	// Hosts commonly emit link-local gateway addresses with an interface zone
	// ("fe80::1%en0"). netip.Prefix.Contains returns false for zoned addrs, so
	// we strip the zone during normalize so gateway-ip CIDR matchers still hit.
	c := &NetworkContext{
		Version: 1,
		Interfaces: []InterfaceContext{
			{Name: "wlan0", GatewayIP: "fe80::1%en0"},
		},
	}
	assert.NoError(t, c.NormalizeAndValidate())
	assert.Equal(t, "fe80::1", c.Interfaces[0].GatewayIP)
	assert.Equal(t, "", c.Interfaces[0].gatewayIPParsed.Zone())
}

func TestNormalize_SubnetsDedupAfterMasked(t *testing.T) {
	// "10.5.0.0/8" and "10.0.0.0/8" mask to the same prefix; dedupe must catch that.
	c := &NetworkContext{
		Version: 1,
		Interfaces: []InterfaceContext{
			{Name: "wlan0", Subnets: []string{"10.5.0.0/8", "10.0.0.0/8"}},
		},
	}
	assert.NoError(t, c.NormalizeAndValidate())
	assert.Equal(t, []string{"10.0.0.0/8"}, c.Interfaces[0].Subnets)
}

func TestValidate(t *testing.T) {
	ttl0, ttlNeg, ttlBig, ttlOK := 0, -1, MaxTTLSeconds+1, 60

	validIface := InterfaceContext{Name: "wlan0"}

	cases := []struct {
		name   string
		ctx    NetworkContext
		errSub string // "" means no error
	}{
		{"valid empty interfaces", NetworkContext{Version: 1}, ""},
		{"valid single iface", NetworkContext{Version: 1, Interfaces: []InterfaceContext{validIface}}, ""},
		{"version 0 rejected (no silent promotion)", NetworkContext{Version: 0}, "invalid version"},
		{"version unsupported", NetworkContext{Version: 2}, "invalid version"},
		{"ttl nil sticky", NetworkContext{Version: 1}, ""},
		{"ttl positive", NetworkContext{Version: 1, TTL: &ttlOK}, ""},
		{"ttl zero", NetworkContext{Version: 1, TTL: &ttl0}, "invalid ttl"},
		{"ttl negative", NetworkContext{Version: 1, TTL: &ttlNeg}, "invalid ttl"},
		{"ttl too large", NetworkContext{Version: 1, TTL: &ttlBig}, "invalid ttl"},
		{"iface name required", NetworkContext{Version: 1, Interfaces: []InterfaceContext{{}}}, "name: empty"},
		{"iface name too long", NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: strings.Repeat("x", 256)}}}, "name: 256 bytes"},
		{"ssid too long", NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", SSID: strings.Repeat("a", 33)}}}, "ssid: 33 bytes"},
		{"ssid at limit", NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", SSID: strings.Repeat("a", 32)}}}, ""},
		{"bssid invalid", NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", BSSID: "xx:yy:zz:11:22:33"}}}, "bssid"},
		{"gateway_ip invalid", NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", GatewayIP: "999.9.9.9"}}}, "gateway_ip"},
		{"iface_type invalid", NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", IfaceType: "wire"}}}, "iface_type"},
		{"gateway_mac without gateway_ip", NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", GatewayMAC: "aa:bb:cc:dd:ee:ff"}}}, "gateway_mac: filled but gateway_ip is empty"},
		{"gateway_mac+gateway_ip ok", NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", GatewayIP: "10.0.0.1", GatewayMAC: "aa:bb:cc:dd:ee:ff"}}}, ""},
		{"subnets invalid entry", NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0", Subnets: []string{"10.0.0.0/8", "not-a-cidr"}}}}, "subnets[1]"},
		{"duplicate iface name", NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "wlan0"}, {Name: "wlan0"}}}, "duplicate name"},
		{"dns_suffix with space", NetworkContext{Version: 1, DNSSuffix: []string{"corp example"}}, "dns_suffix"},
		{"dns_suffix with comma rejected", NetworkContext{Version: 1, DNSSuffix: []string{"a,b"}}, "dns_suffix"},
		{"too many interfaces", NetworkContext{Version: 1, Interfaces: makeIfaces(MaxInterfaces + 1)}, "invalid interfaces: 33 entries"},
		{"at max interfaces", NetworkContext{Version: 1, Interfaces: makeIfaces(MaxInterfaces)}, ""},
	}
	for _, tc := range cases {
		c := tc.ctx
		err := c.NormalizeAndValidate()
		if tc.errSub == "" {
			assert.NoError(t, err, "case %q", tc.name)
		} else {
			assert.ErrorContains(t, err, tc.errSub, "case %q", tc.name)
		}
	}
}

func makeIfaces(n int) []InterfaceContext {
	out := make([]InterfaceContext, n)
	for i := range out {
		out[i].Name = "if" + string(rune('a'+i/26)) + string(rune('a'+i%26))
	}
	return out
}

// TestFingerprint exercises the semantic invariants of the fingerprint algorithm.
func TestFingerprint(t *testing.T) {
	ttl := 60
	base := NetworkContext{
		Version: 1,
		Interfaces: []InterfaceContext{
			{Name: "wlan0", SSID: "office", IfaceType: "wifi"},
		},
		DNSSuffix: []string{"corp.example.com"},
	}

	// TTL must not affect fingerprint.
	a := base
	c := base
	c.TTL = &ttl

	for _, x := range []*NetworkContext{&a, &c} {
		_ = x.NormalizeAndValidate()
	}
	assert.Equal(t, a.Fingerprint(), c.Fingerprint(), "TTL excluded from fingerprint")

	// IPv6 canonicalization: three equivalent forms collapse to one fingerprint.
	ipForms := []string{"2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:DB8:0::1"}
	var fps []string
	for _, ip := range ipForms {
		c := NetworkContext{
			Version: 1,
			Interfaces: []InterfaceContext{
				{Name: "wlan0", GatewayIP: ip},
			},
		}
		_ = c.NormalizeAndValidate()
		fps = append(fps, c.Fingerprint())
	}
	assert.Equal(t, fps[0], fps[1])
	assert.Equal(t, fps[0], fps[2])

	// Length-prefix in write_kv: a value containing "name=...\n" must not
	// collide with a context where those markers are real field structure.
	a1 := NetworkContext{
		Version: 1,
		Interfaces: []InterfaceContext{
			{Name: "wlan0", SSID: "x\ngateway_ip=10.0.0.1"},
		},
	}
	a2 := NetworkContext{
		Version: 1,
		Interfaces: []InterfaceContext{
			{Name: "wlan0", SSID: "x", GatewayIP: "10.0.0.1"},
		},
	}
	_ = a1.NormalizeAndValidate()
	_ = a2.NormalizeAndValidate()
	assert.NotEqual(t, a1.Fingerprint(), a2.Fingerprint())

	// Iface order independence: normalize sorts by name, so host insertion
	// order must not affect the fingerprint.
	f1 := NetworkContext{
		Version: 1,
		Interfaces: []InterfaceContext{
			{Name: "en0", IfaceType: "ethernet"},
			{Name: "wlan0", IfaceType: "wifi"},
		},
	}
	f2 := NetworkContext{
		Version: 1,
		Interfaces: []InterfaceContext{
			{Name: "wlan0", IfaceType: "wifi"},
			{Name: "en0", IfaceType: "ethernet"},
		},
	}
	_ = f1.NormalizeAndValidate()
	_ = f2.NormalizeAndValidate()
	assert.Equal(t, f1.Fingerprint(), f2.Fingerprint(), "iface insertion order must not change fingerprint")
}

// TestFingerprint_Stable checks that the fingerprint output format is 16-char
// lower-case hex and produces a stable value for a fixed input. Cross-impl
// byte-parity golden fixtures (validating against any future language-port
// implementation) are added later once a second implementation exists.
func TestFingerprint_Stable(t *testing.T) {
	c := NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "en0"}}}
	assert.NoError(t, c.NormalizeAndValidate())
	fp1 := c.Fingerprint()
	fp2 := c.Fingerprint()
	assert.Equal(t, fp1, fp2, "fingerprint is deterministic")
	assert.Len(t, fp1, 16, "fingerprint is 16 hex chars (fnv64a)")
	for _, ch := range fp1 {
		assert.True(t, (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'), "lowercase hex only: got %q", fp1)
	}
}

// TestFingerprint_Pinned locks the current Go implementation against silent
// algorithm drift (field order swap, hash family change, length-prefix
// encoding change). If any of these shift, the test breaks loudly — and the
// operator updating the expected values must consciously accept that they
// are also breaking any cross-impl byte parity relying on the old hashes.
//
// Not a cross-impl golden fixture; that comes when a second implementation
// lands. These are local self-consistency anchors only.
func TestFingerprint_Pinned(t *testing.T) {
	tVal, fVal := true, false
	cases := []struct {
		name string
		ctx  NetworkContext
		want string
	}{
		{
			"empty",
			NetworkContext{Version: 1},
			"e124fe9cbeefe00a",
		},
		{
			"single name only",
			NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "en0"}}},
			"209db35aa391d1ab",
		},
		{
			"rich single iface",
			NetworkContext{
				Version: 1,
				Interfaces: []InterfaceContext{
					{
						Name:       "wlan0",
						IfaceType:  "wifi",
						SSID:       "office",
						BSSID:      "aa:bb:cc:dd:ee:00",
						GatewayIP:  "10.0.0.1",
						GatewayMAC: "11:22:33:44:55:66",
						Subnets:    []string{"10.0.0.0/24"},
						Metered:    &fVal,
					},
				},
				DNSSuffix: []string{"corp.example.com"},
			},
			"44642fb47eb57a92",
		},
		{
			"two ifaces",
			NetworkContext{
				Version: 1,
				Interfaces: []InterfaceContext{
					{Name: "en0", IfaceType: "ethernet"},
					{Name: "wg0", IfaceType: "vpn", Metered: &tVal},
				},
			},
			"f8c3ef1ec380d486",
		},
	}
	for _, tc := range cases {
		c := tc.ctx
		assert.NoError(t, c.NormalizeAndValidate(), "case %q", tc.name)
		assert.Equal(t, tc.want, c.Fingerprint(), "case %q fingerprint drift", tc.name)
	}
}

// TestFingerprint_MeteredTriState pins the tri-state metered encoding in
// the fingerprint. The three distinct values null / true / false must
// produce three distinct hashes — that's what lets a cross-impl
// implementation (e.g. host-side Rust) reach byte parity even though JSON
// can express all three states.
func TestFingerprint_MeteredTriState(t *testing.T) {
	tVal, fVal := true, false
	ctxNull := norm(t, &NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "en0"}}})
	ctxTrue := norm(t, &NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "en0", Metered: &tVal}}})
	ctxFalse := norm(t, &NetworkContext{Version: 1, Interfaces: []InterfaceContext{{Name: "en0", Metered: &fVal}}})

	fpNull, fpTrue, fpFalse := ctxNull.Fingerprint(), ctxTrue.Fingerprint(), ctxFalse.Fingerprint()
	assert.NotEqual(t, fpNull, fpTrue, "metered=null vs metered=true must differ")
	assert.NotEqual(t, fpNull, fpFalse, "metered=null vs metered=false must differ")
	assert.NotEqual(t, fpTrue, fpFalse, "metered=true vs metered=false must differ")
}

// TestFingerprint_Idempotent deep-copies a context, repeats normalize, and
// verifies both the resulting fingerprint and the canonical stored fields
// stay identical across repeated calls.
func TestFingerprint_Idempotent(t *testing.T) {
	c := NetworkContext{
		Version: 1,
		Interfaces: []InterfaceContext{
			{Name: "wlan0", SSID: "office", Subnets: []string{"10.0.0.0/8"}, BSSID: "AA-BB-CC-DD-EE-FF"},
		},
		DNSSuffix: []string{"CORP.example.com"},
	}
	assert.NoError(t, c.NormalizeAndValidate())
	fp1 := c.Fingerprint()

	// Second pass — should be a no-op even after a fresh normalize().
	c.normalize()
	assert.NoError(t, c.validate())
	fp2 := c.Fingerprint()
	assert.Equal(t, fp1, fp2, "Fingerprint stable across repeated NormalizeAndValidate")
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", c.Interfaces[0].BSSID, "BSSID stays canonical")
	assert.Equal(t, []string{"10.0.0.0/8"}, c.Interfaces[0].Subnets)
	assert.Equal(t, []string{"corp.example.com"}, c.DNSSuffix)
}

func TestJSONDecoding(t *testing.T) {
	// JSON null, missing, and zero are three distinct states for TTL and Metered.
	cases := []struct {
		name string
		in   string
		want func(t *testing.T, c *NetworkContext)
	}{
		{"ttl missing → nil", `{"version":1,"interfaces":[]}`, func(t *testing.T, c *NetworkContext) {
			assert.Nil(t, c.TTL)
		}},
		{"ttl null → nil", `{"version":1,"interfaces":[],"ttl":null}`, func(t *testing.T, c *NetworkContext) {
			assert.Nil(t, c.TTL)
		}},
		{"ttl 0 → *0", `{"version":1,"interfaces":[],"ttl":0}`, func(t *testing.T, c *NetworkContext) {
			assert.NotNil(t, c.TTL)
			assert.Equal(t, 0, *c.TTL)
		}},
		{"iface metered null → nil", `{"version":1,"interfaces":[{"name":"en0","metered":null}]}`, func(t *testing.T, c *NetworkContext) {
			assert.Len(t, c.Interfaces, 1)
			assert.Nil(t, c.Interfaces[0].Metered)
		}},
		{"iface metered false → *false", `{"version":1,"interfaces":[{"name":"en0","metered":false}]}`, func(t *testing.T, c *NetworkContext) {
			assert.Len(t, c.Interfaces, 1)
			assert.NotNil(t, c.Interfaces[0].Metered)
			assert.False(t, *c.Interfaces[0].Metered)
		}},
		{"iface metered true → *true", `{"version":1,"interfaces":[{"name":"en0","metered":true}]}`, func(t *testing.T, c *NetworkContext) {
			assert.Len(t, c.Interfaces, 1)
			assert.NotNil(t, c.Interfaces[0].Metered)
			assert.True(t, *c.Interfaces[0].Metered)
		}},
		{"dns_suffix array", `{"version":1,"interfaces":[],"dns_suffix":["corp","home"]}`, func(t *testing.T, c *NetworkContext) {
			assert.Equal(t, []string{"corp", "home"}, c.DNSSuffix)
		}},
	}
	for _, tc := range cases {
		var c NetworkContext
		assert.NoError(t, json.Unmarshal([]byte(tc.in), &c), "case %q", tc.name)
		tc.want(t, &c)
	}
}

func TestJSONDecoding_RejectsMissingRequiredFields(t *testing.T) {
	// version and interfaces are wire-required. Missing either is a
	// malformed_body error at the REST layer.
	cases := []struct {
		name string
		in   string
	}{
		{"missing version", `{"interfaces":[]}`},
		{"missing interfaces", `{"version":1}`},
		{"both missing", `{}`},
		{"version null", `{"version":null,"interfaces":[]}`},
		{"interfaces null", `{"version":1,"interfaces":null}`},
	}
	for _, tc := range cases {
		var c NetworkContext
		err := json.Unmarshal([]byte(tc.in), &c)
		assert.Error(t, err, "case %q", tc.name)
	}
}

func TestJSONDecoding_RejectsScalarDNSSuffix(t *testing.T) {
	// dns_suffix is wire-required to be []string. A scalar form triggers a
	// json.Unmarshal type mismatch, which REST handlers surface as
	// malformed_body.
	var c NetworkContext
	err := json.Unmarshal([]byte(`{"version":1,"interfaces":[],"dns_suffix":"corp"}`), &c)
	assert.Error(t, err)
}

func TestIsValidIfaceType(t *testing.T) {
	for _, s := range []string{"", "wifi", "ethernet", "cellular", "wwan", "vpn", "loopback", "other"} {
		assert.True(t, IsValidIfaceType(s), "want valid for %q", s)
	}
	for _, s := range []string{"tun", "wire", "WIFI", "cell"} {
		assert.False(t, IsValidIfaceType(s), "want invalid for %q", s)
	}
}
