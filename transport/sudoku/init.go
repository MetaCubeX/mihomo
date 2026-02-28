package sudoku

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/metacubex/edwards25519"
	"github.com/metacubex/mihomo/transport/sudoku/crypto"
	"github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

func NewTable(key string, tableType string) *sudoku.Table {
	table, err := NewTableWithCustom(key, tableType, "")
	if err != nil {
		panic(fmt.Sprintf("[Sudoku] failed to init tables: %v", err))
	}
	return table
}

func NewTableWithCustom(key string, tableType string, customTable string) (*sudoku.Table, error) {
	table, err := sudoku.NewTableWithCustom(key, tableType, customTable)
	if err != nil {
		return nil, err
	}
	return table, nil
}

// ClientAEADSeed returns a canonical "seed" that is stable between client private key material and server public key.
func ClientAEADSeed(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}

	b, err := hex.DecodeString(key)
	if err != nil {
		return key
	}

	// Client-side key material can be:
	//   - split private key: 64 bytes hex (r||k)
	//   - master private scalar: 32 bytes hex (x)
	//   - PSK string: non-hex
	//
	// We intentionally do NOT treat a 32-byte hex as a public key here; the client is expected
	// to carry private material. Server-side should use ServerAEADSeed for public keys.
	switch len(b) {
	case 64:
	case 32:
	default:
		return key
	}
	if recovered, err := crypto.RecoverPublicKey(key); err == nil {
		return crypto.EncodePoint(recovered)
	}
	return key
}

// ServerAEADSeed returns a canonical seed for server-side configuration.
//
// When key is a public key (32-byte compressed point, hex), it returns the canonical point encoding.
// When key is private key material (split/master scalar), it derives and returns the public key.
func ServerAEADSeed(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}

	b, err := hex.DecodeString(key)
	if err != nil {
		return key
	}

	// Prefer interpreting 32-byte hex as a public key point, to avoid accidental scalar parsing.
	if len(b) == 32 {
		if p, err := new(edwards25519.Point).SetBytes(b); err == nil {
			return hex.EncodeToString(p.Bytes())
		}
	}

	// Fall back to client-side rules for private key materials / other formats.
	return ClientAEADSeed(key)
}

// GenKeyPair generates a client "available private key" and the corresponding server public key.
func GenKeyPair() (privateKey, publicKey string, err error) {
	pair, err := crypto.GenerateMasterKey()
	if err != nil {
		return "", "", err
	}
	availablePrivateKey, err := crypto.SplitPrivateKey(pair.Private)
	if err != nil {
		return "", "", err
	}
	return availablePrivateKey, crypto.EncodePoint(pair.Public), nil
}
