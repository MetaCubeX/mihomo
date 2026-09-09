package outbound

import (
	"testing"

	"github.com/metacubex/mihomo/common/structure"
)

func TestEasyTierPeerUnmarshalText(t *testing.T) {
	var peer EasyTierPeer
	if err := peer.UnmarshalText([]byte(" tcp://192.0.2.10:11010 ")); err != nil {
		t.Fatal(err)
	}
	if peer.URI != "tcp://192.0.2.10:11010" || peer.PeerPublicKey != "" {
		t.Fatalf("got %+v", peer)
	}
}

func TestEasyTierOptionDecodesStringAndPinnedPeers(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	var option EasyTierOption
	err := decoder.Decode(map[string]any{
		"name":         "easytier",
		"network-name": "example",
		"secure-mode":  true,
		"peers": []any{
			"tcp://192.0.2.10:11010",
			map[string]any{
				"uri":             "tcp://relay.example.com:11010",
				"peer-public-key": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
			},
		},
	}, &option)
	if err != nil {
		t.Fatal(err)
	}
	if option.SecureMode == nil || !*option.SecureMode {
		t.Fatal("expected secure-mode")
	}
	if len(option.Peers) != 2 {
		t.Fatalf("peers: %+v", option.Peers)
	}
	if option.Peers[0].URI != "tcp://192.0.2.10:11010" {
		t.Fatalf("string peer: %+v", option.Peers[0])
	}
	if option.Peers[1].URI != "tcp://relay.example.com:11010" || option.Peers[1].PeerPublicKey == "" {
		t.Fatalf("pinned peer: %+v", option.Peers[1])
	}
}
