package miu

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/transport/anytls/padding"
)

// testdata/miu-padding-profile-v1.json is shared with the miu repo and the
// Swift client: every implementation has to produce the same scheme text.
type derivedVectors struct {
	Vectors []struct {
		ID     string `json:"id"`
		PSK    string `json:"psk"`
		Token  string `json:"auth_token_sha256_hex"`
		Scheme struct {
			Text string `json:"text"`
			MD5  string `json:"md5"`
		} `json:"scheme"`
	} `json:"vectors"`
}

func loadDerivedVectors(t *testing.T) derivedVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/miu-padding-profile-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v derivedVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return v
}

func TestDerivedSchemeVectors(t *testing.T) {
	for _, v := range loadDerivedVectors(t).Vectors {
		token := sha256.Sum256([]byte(strings.TrimSpace(v.PSK)))
		if hex.EncodeToString(token[:]) != v.Token {
			t.Fatalf("%s: token %x", v.ID, token)
		}
		text, err := derivedScheme(token)
		if err != nil {
			t.Fatalf("%s: %v", v.ID, err)
		}
		if text != v.Scheme.Text {
			t.Fatalf("%s: scheme\n%s\nwant\n%s", v.ID, text, v.Scheme.Text)
		}
		if got := fmt.Sprintf("%x", md5.Sum([]byte(text))); got != v.Scheme.MD5 {
			t.Fatalf("%s: md5 %s", v.ID, got)
		}
		if p := padding.NewPaddingFactory([]byte(text)); p == nil || p.Md5 != v.Scheme.MD5 {
			t.Fatalf("%s: not a usable scheme", v.ID)
		}
	}
}

// The derived scheme stays within the bounds every implementation relies on.
func TestDerivedSchemeBounds(t *testing.T) {
	for i := 0; i < 2000; i++ {
		text, err := derivedScheme(sha256.Sum256([]byte(fmt.Sprintf("bounds-psk-%04d-xxxxxxxx", i))))
		if err != nil {
			t.Fatal(err)
		}
		p := padding.NewPaddingFactory([]byte(text))
		if p == nil || p.Stop < 5 || p.Stop > 10 {
			t.Fatalf("stop: %q", text)
		}
		upper := 0
		for key, spec := range parseKV(text) {
			if key == "stop" {
				continue
			}
			for _, part := range strings.Split(spec, ",") {
				if part == "c" {
					continue
				}
				a, b, ok := strings.Cut(part, "-")
				lo, e1 := strconv.Atoi(a)
				hi, e2 := strconv.Atoi(b)
				if !ok || e1 != nil || e2 != nil || lo >= hi {
					t.Fatalf("bad range %q", part)
				}
				if key == "0" && (lo < 24 || hi > 64) {
					t.Fatalf("auth range %q", part)
				}
				upper += hi
			}
		}
		if upper > derivedBudget {
			t.Fatalf("upper bound %d: %q", upper, text)
		}
		total := 0
		for pkt := uint32(0); pkt < p.Stop; pkt++ {
			sizes := p.GenerateRecordPayloadSizes(pkt)
			if len(sizes) == 0 {
				t.Fatalf("packet %d has no sizes: %q", pkt, text)
			}
			for _, s := range sizes {
				if s == padding.CheckMark {
					continue
				}
				if pkt > 0 && (s < 128 || s >= 8192) {
					t.Fatalf("record size %d: %q", s, text)
				}
				total += s
			}
		}
		if total > derivedBudget {
			t.Fatalf("over budget %d: %q", total, text)
		}
	}
}

// A new client starts out with the scheme derived from its PSK, different users
// get different schemes, a configured scheme wins, a broken one is refused.
func TestClientInitialScheme(t *testing.T) {
	v := loadDerivedVectors(t).Vectors[0]
	c, err := NewClient(ClientConfig{PSK: "  " + v.PSK + "\n", Dial: func(context.Context) (net.Conn, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := c.padding; string(got.RawScheme) != v.Scheme.Text || got.Md5 != v.Scheme.MD5 {
		t.Fatalf("initial scheme: %q", got.RawScheme)
	}

	other, err := NewClient(ClientConfig{PSK: testPSK, Dial: func(context.Context) (net.Conn, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if other.padding.Md5 == v.Scheme.MD5 {
		t.Fatal("two PSKs share a scheme")
	}

	explicit := "stop=2\n0=10-20\n1=200-300"
	c2, err := NewClient(ClientConfig{PSK: testPSK, PaddingScheme: explicit, Dial: func(context.Context) (net.Conn, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if string(c2.padding.RawScheme) != explicit {
		t.Fatalf("explicit scheme: %q", c2.padding.RawScheme)
	}

	if _, err := NewClient(ClientConfig{PSK: testPSK, PaddingScheme: "0=1-2", Dial: func(context.Context) (net.Conn, error) { return nil, nil }}); err == nil {
		t.Fatal("a scheme without stop is accepted")
	}
}
