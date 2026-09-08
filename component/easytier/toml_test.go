package easytier

import (
	"strings"
	"testing"
)

func boolPtr(v bool) *bool { return &v }

func TestRenderTOMLDefaultNoListenerRequiresPeers(t *testing.T) {
	_, err := Config{NetworkName: "example"}.RenderTOML()
	if err == nil {
		t.Fatal("expected missing peers to fail")
	}
}

func TestRenderTOMLNoListenerFalseDefaultListener(t *testing.T) {
	toml, err := Config{
		NetworkName: "example",
		NoListener:  boolPtr(false),
	}.RenderTOML()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(toml, `listeners = ["tcp://0.0.0.0:11010"]`) {
		t.Fatalf("missing default listener:\n%s", toml)
	}
	if !strings.Contains(toml, "no_tun = true") || !strings.Contains(toml, "bind_device = false") {
		t.Fatalf("missing required flags:\n%s", toml)
	}
}

func TestRenderTOMLExplicitEmptyListenersWithPeers(t *testing.T) {
	toml, err := Config{
		NetworkName:   "example",
		NetworkSecret: "secret",
		Peers:         []string{"tcp://192.0.2.10:11010"},
		Hostname:      "node-a",
		IPv4:          "10.144.0.1/24",
	}.RenderTOML()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(toml, "listeners = []") {
		t.Fatalf("expected empty listeners:\n%s", toml)
	}
	if !strings.Contains(toml, "[[peer]]") || !strings.Contains(toml, `uri = "tcp://192.0.2.10:11010"`) {
		t.Fatalf("missing peer:\n%s", toml)
	}
}

func TestApplyRequiredFlagsInjectsNoTun(t *testing.T) {
	got := ApplyRequiredFlags("[network_identity]\nnetwork_name = \"n\"\n", false)
	if !strings.Contains(got, "[flags]") || !strings.Contains(got, "no_tun = true") {
		t.Fatalf("did not inject no_tun:\n%s", got)
	}
	if strings.Contains(got, "bind_device") {
		t.Fatalf("raw config should not force bind_device:\n%s", got)
	}
}

func TestApplyRequiredFlagsReplacesNoTun(t *testing.T) {
	got := ApplyRequiredFlags("[flags]\nno_tun = false\nmtu = 1200\n", true)
	if !strings.Contains(got, "no_tun = true") {
		t.Fatalf("did not replace no_tun:\n%s", got)
	}
	if !strings.Contains(got, "bind_device = false") {
		t.Fatalf("missing bind_device:\n%s", got)
	}
	if !strings.Contains(got, "mtu = 1200") {
		t.Fatalf("lost existing flag:\n%s", got)
	}
}

func TestNoListenerConflict(t *testing.T) {
	err := Config{
		NetworkName: "example",
		NoListener:  boolPtr(true),
		Listeners:   []string{"tcp://0.0.0.0:11010"},
	}.ValidateStructured()
	if err == nil {
		t.Fatal("expected conflict")
	}
}

func TestRenderTOMLManualIPv4WithoutPrefix(t *testing.T) {
	toml, err := Config{
		NetworkName:   "example",
		NetworkSecret: "example",
		IPv4:          "10.144.0.10",
		Peers:         []string{"tcp://192.0.2.10:11010"},
	}.RenderTOML()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(toml, `ipv4 = "10.144.0.10"`) {
		t.Fatalf("missing manual ipv4:\n%s", toml)
	}
	if !strings.Contains(toml, `uri = "tcp://192.0.2.10:11010"`) {
		t.Fatalf("missing peer:\n%s", toml)
	}
}
