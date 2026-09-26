//go:build with_gvisor && !no_tailscale

package outbound

import (
	"net/netip"
	"testing"
)

func TestBuildTailscaleMaskedPrefsAdvertiseRoutes(t *testing.T) {
	mp, err := buildTailscaleMaskedPrefs(TailscaleOption{
		AdvertiseRoutes: []string{" 192.168.1.5/24 ", "fd12:3456:789a::1/64"},
	})
	if err != nil {
		t.Fatalf("build prefs: %v", err)
	}
	if mp == nil || !mp.AdvertiseRoutesSet {
		t.Fatal("expected advertised routes to be set")
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("fd12:3456:789a::/64"),
	}
	if len(mp.AdvertiseRoutes) != len(want) {
		t.Fatalf("routes = %v, want %v", mp.AdvertiseRoutes, want)
	}
	for i := range want {
		if mp.AdvertiseRoutes[i] != want[i] {
			t.Fatalf("routes = %v, want %v", mp.AdvertiseRoutes, want)
		}
	}
}

func TestBuildTailscaleMaskedPrefsClearsAdvertiseRoutes(t *testing.T) {
	mp, err := buildTailscaleMaskedPrefs(TailscaleOption{
		AdvertiseRoutes: []string{},
	})
	if err != nil {
		t.Fatalf("build prefs: %v", err)
	}
	if mp == nil || !mp.AdvertiseRoutesSet {
		t.Fatal("expected an explicit empty route list to clear advertised routes")
	}
	if len(mp.AdvertiseRoutes) != 0 {
		t.Fatalf("routes = %v, want none", mp.AdvertiseRoutes)
	}
}

func TestBuildTailscaleMaskedPrefsOmitsAdvertiseRoutes(t *testing.T) {
	mp, err := buildTailscaleMaskedPrefs(TailscaleOption{})
	if err != nil {
		t.Fatalf("build prefs: %v", err)
	}
	if mp != nil {
		t.Fatalf("prefs = %#v, want nil when advertise-routes is omitted", mp)
	}
}

func TestBuildTailscaleMaskedPrefsAdvertiseRoutesErrors(t *testing.T) {
	cases := []TailscaleOption{
		{AdvertiseRoutes: []string{"not-a-prefix"}},
		{AdvertiseRoutes: []string{""}},
		{AdvertiseRoutes: []string{"192.168.1.0/24", "192.168.1.9/24"}},
		{AdvertiseRoutes: []string{"0.0.0.0/0", "::/0"}, ExitNode: "100.64.0.1"},
	}
	for _, option := range cases {
		if _, err := buildTailscaleMaskedPrefs(option); err == nil {
			t.Fatalf("option %#v: expected error", option)
		}
	}
}

func TestBuildTailscaleMaskedPrefsExitNodeWithPartialDefaultRoute(t *testing.T) {
	mp, err := buildTailscaleMaskedPrefs(TailscaleOption{
		AdvertiseRoutes: []string{"0.0.0.0/0"},
		ExitNode:        "auto:any",
	})
	if err != nil {
		t.Fatalf("build prefs: %v", err)
	}
	if mp == nil || !mp.AdvertiseRoutesSet || !mp.AutoExitNodeSet {
		t.Fatalf("prefs = %#v, want both advertised routes and auto exit node", mp)
	}
}
