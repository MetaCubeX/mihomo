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
		require.Equal(t, pub, ServerAEADSeed(pub))
		require.Equal(t, pub, ServerAEADSeed(priv))
	}
}

func TestClientAEADSeed_Supports32ByteMasterScalar(t *testing.T) {
	var seed [64]byte
	_, err := rand.Read(seed[:])
	require.NoError(t, err)

	s, err := edwards25519.NewScalar().SetUniformBytes(seed[:])
	require.NoError(t, err)

	keyHex := hex.EncodeToString(s.Bytes())
	require.Len(t, keyHex, 64)
	require.NotEqual(t, keyHex, ClientAEADSeed(keyHex))
	require.Equal(t, ClientAEADSeed(keyHex), ServerAEADSeed(ClientAEADSeed(keyHex)))
}

func TestServerAEADSeed_LeavesPublicKeyAsIs(t *testing.T) {
	for i := 0; i < 64; i++ {
		priv, pub, err := GenKeyPair()
		require.NoError(t, err)
		require.Equal(t, pub, ServerAEADSeed(pub))
		require.Equal(t, pub, ServerAEADSeed(priv))
	}
}
