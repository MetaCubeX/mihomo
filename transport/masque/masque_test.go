package masque

import (
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go/http3"
	"github.com/stretchr/testify/require"
)

func TestParseTunnelURL(t *testing.T) {
	t.Run("default template", func(t *testing.T) {
		u, err := ParseTunnelURL("https://proxy.example/.well-known/masque/ip/{target}/{ipproto}/")
		require.NoError(t, err)
		require.Equal(t, "proxy.example", u.Host)
		// URI Template expansion may percent-encode the reserved asterisk on
		// the wire; URL.Path is the decoded RFC 9484 wildcard value.
		require.Equal(t, "/.well-known/masque/ip/*/*/", u.Path)
	})

	t.Run("query template", func(t *testing.T) {
		u, err := ParseTunnelURL("https://proxy.example/masque/ip{?target,ipproto}")
		require.NoError(t, err)
		require.Equal(t, "*", u.Query().Get("target"))
		require.Equal(t, "*", u.Query().Get("ipproto"))
	})

	t.Run("already expanded", func(t *testing.T) {
		u, err := ParseTunnelURL("https://proxy.example/.well-known/masque/ip/*/*/")
		require.NoError(t, err)
		require.Equal(t, "/.well-known/masque/ip/*/*/", u.Path)
	})
}

func TestParseTunnelURLRejectsInvalidTemplates(t *testing.T) {
	tests := map[string]string{
		"non TLS":             "http://proxy.example/masque",
		"missing authority":   "https:///masque",
		"missing path":        "https://proxy.example",
		"userinfo":            "https://user@proxy.example/masque",
		"unknown variable":    "https://proxy.example/{tenant}",
		"authority variable":  "https://{target}/masque",
		"reserved expansion":  "https://proxy.example/{+target}",
		"fragment expansion":  "https://proxy.example/{#target}",
		"path expansion":      "https://proxy.example/{/target}",
		"level four modifier": "https://proxy.example/{target:3}",
		"fragment":            "https://proxy.example/masque#fragment",
		"whitespace":          "https://proxy.example/a b",
		"unicode":             "https://proxy.example/隧道",
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseTunnelURL(raw)
			require.Error(t, err)
		})
	}
}

func TestRequestHeaders(t *testing.T) {
	original := http.Header{
		"Authorization":             []string{"Bearer token"},
		http3.CapsuleProtocolHeader: []string{"?0"},
	}
	headers, err := requestHeaders(original)
	require.NoError(t, err)
	require.Equal(t, "Bearer token", headers.Get("Authorization"))
	require.Equal(t, CapsuleProtocolHeaderValue, headers.Get(http3.CapsuleProtocolHeader))
	require.Equal(t, "?0", original.Get(http3.CapsuleProtocolHeader), "the caller's headers must not be mutated")

	_, err = requestHeaders(http.Header{":authority": []string{"attacker.example"}})
	require.ErrorContains(t, err, "pseudo-header")
}

func TestValidateCapsuleProtocol(t *testing.T) {
	valid := http.Header{http3.CapsuleProtocolHeader: []string{"?1"}}
	require.NoError(t, validateCapsuleProtocol(valid))

	tests := map[string]http.Header{
		"missing": {},
		"false":   {http3.CapsuleProtocolHeader: []string{"?0"}},
		"integer": {http3.CapsuleProtocolHeader: []string{"1"}},
		"invalid": {http3.CapsuleProtocolHeader: []string{"not a structured field"}},
	}
	for name, headers := range tests {
		t.Run(name, func(t *testing.T) {
			require.Error(t, validateCapsuleProtocol(headers))
		})
	}
}
