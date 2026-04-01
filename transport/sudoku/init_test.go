package sudoku

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/metacubex/edwards25519"
	"github.com/stretchr/testify/require"
)

func TestClientAEADSeed_IsStableForPrivAndPub(t *testing.T) {
	for i := 0; i < 64; i++ {
		priv, pub, err := GenKeyPair()
		require.NoError(t, err)

		require.Equal(t, pub, ClientAEADSeed(priv))
		require.Equal(t, pub, ClientAEADSeed(pub))
		require.Equal(t, pub, ServerAEADSeed(pub))
		require.Equal(t, pub, ServerAEADSeed(priv))
	}
}

func TestClientAEADSeed_Supports32ByteMasterScalar(t *testing.T) {
	for i := 0; i < 256; i++ {
		var seed [64]byte
		_, err := rand.Read(seed[:])
		require.NoError(t, err)

		s, err := edwards25519.NewScalar().SetUniformBytes(seed[:])
		require.NoError(t, err)

		keyHex := hex.EncodeToString(s.Bytes())
		require.Len(t, keyHex, 64)

		// 32-byte hex is ambiguous: it can be either a master scalar or an
		// already-compressed public key. Public-key encoding wins when both parse.
		if _, err := new(edwards25519.Point).SetBytes(s.Bytes()); err == nil {
			continue
		}

		require.NotEqual(t, keyHex, ClientAEADSeed(keyHex))
		require.Equal(t, ClientAEADSeed(keyHex), ServerAEADSeed(ClientAEADSeed(keyHex)))
		return
	}

	t.Fatal("failed to generate an unambiguous 32-byte master scalar")
}

func TestServerAEADSeed_LeavesPublicKeyAsIs(t *testing.T) {
	for i := 0; i < 64; i++ {
		priv, pub, err := GenKeyPair()
		require.NoError(t, err)
		require.Equal(t, pub, ServerAEADSeed(pub))
		require.Equal(t, pub, ServerAEADSeed(priv))
	}
}
