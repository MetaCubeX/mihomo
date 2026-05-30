package outbound

import (
	"testing"

	shadowtls "github.com/metacubex/mihomo/transport/sing-shadowtls"

	"github.com/stretchr/testify/assert"
)

func TestNewShadowTLSOption(t *testing.T) {
	t.Run("nil when no password", func(t *testing.T) {
		assert.Nil(t, newShadowTLSOption(SnellOption{}))
		assert.Nil(t, newShadowTLSOption(SnellOption{ShadowTLSSNI: "example.com"}))
	})

	t.Run("maps fields", func(t *testing.T) {
		opt := newShadowTLSOption(SnellOption{
			ClientFingerprint:       "chrome",
			ShadowTLSPassword:       "pw",
			ShadowTLSSNI:            "example.com",
			ShadowTLSVersion:        3,
			ShadowTLSSkipCertVerify: true,
		})
		if assert.NotNil(t, opt) {
			assert.Equal(t, "pw", opt.Password)
			assert.Equal(t, "example.com", opt.Host)
			assert.Equal(t, 3, opt.Version)
			assert.Equal(t, "chrome", opt.ClientFingerprint)
			assert.True(t, opt.SkipCertVerify)
		}
	})

	t.Run("version defaults to 2", func(t *testing.T) {
		opt := newShadowTLSOption(SnellOption{ShadowTLSPassword: "pw"})
		if assert.NotNil(t, opt) {
			assert.Equal(t, 2, opt.Version)
		}
	})

	t.Run("alpn defaults when unset", func(t *testing.T) {
		opt := newShadowTLSOption(SnellOption{ShadowTLSPassword: "pw"})
		if assert.NotNil(t, opt) {
			assert.Equal(t, shadowtls.DefaultALPN, opt.ALPN)
		}
	})

	t.Run("alpn respected when set", func(t *testing.T) {
		opt := newShadowTLSOption(SnellOption{
			ShadowTLSPassword: "pw",
			ShadowTLSALPN:     []string{"h2"},
		})
		if assert.NotNil(t, opt) {
			assert.Equal(t, []string{"h2"}, opt.ALPN)
		}
	})
}
