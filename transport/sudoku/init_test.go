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
	}
}

func TestClientAEADSeed_DoesNotTransform32ByteHex(t *testing.T) {
	// Some compressed points may coincidentally look like valid scalars.
	// Ensure we never "recover" a 32-byte hex key into a different seed.
	var seed [64]byte
	_, err := rand.Read(seed[:])
	require.NoError(t, err)

	s, err := edwards25519.NewScalar().SetUniformBytes(seed[:])
	require.NoError(t, err)

	keyHex := hex.EncodeToString(s.Bytes())
	require.Len(t, keyHex, 64)
	require.Equal(t, keyHex, ClientAEADSeed(keyHex))
}

func TestKIPUserHash_IsStableForPrivAndPub(t *testing.T) {
	for i := 0; i < 64; i++ {
		priv, pub, err := GenKeyPair()
		require.NoError(t, err)
		require.Equal(t, kipUserHashFromKey(priv), kipUserHashFromKey(pub))
	}
}
