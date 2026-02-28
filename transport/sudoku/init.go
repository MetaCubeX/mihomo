package sudoku

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/metacubex/mihomo/log"
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
	start := time.Now()
	table, err := sudoku.NewTableWithCustom(key, tableType, customTable)
	if err != nil {
		return nil, err
	}
	log.Infoln("[Sudoku] Tables initialized (%s, custom=%v) in %v", tableType, customTable != "", time.Since(start))
	return table, nil
}

// ClientAEADSeed returns a canonical "seed" that is stable between client private key material and server public key.
func ClientAEADSeed(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}

	// Only attempt recovery for split private keys (64 bytes hex => 128 hex chars).
	//
	// Public keys are encoded as 32-byte compressed points (also hex), and may coincidentally
	// look like valid scalars. Treating them as scalars would make the derived seed unstable
	// across runs (and break handshake for some generated key pairs).
	if b, err := hex.DecodeString(key); err == nil && len(b) == 64 {
		if recovered, err := crypto.RecoverPublicKey(key); err == nil {
			return crypto.EncodePoint(recovered)
		}
	}
	return key
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
