package sudoku

import (
	"fmt"
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
	if recovered, err := crypto.RecoverPublicKey(key); err == nil {
		return crypto.EncodePoint(recovered)
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
