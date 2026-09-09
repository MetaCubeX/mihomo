package outbound

import "strings"

// EasyTierPeer is one EasyTier entry node.
// YAML accepts either a URI string or an object with uri / peer-public-key.
type EasyTierPeer struct {
	URI           string `proxy:"uri,omitempty"`
	PeerPublicKey string `proxy:"peer-public-key,omitempty"`
}

func (p *EasyTierPeer) UnmarshalText(text []byte) error {
	*p = EasyTierPeer{URI: strings.TrimSpace(string(text))}
	return nil
}
