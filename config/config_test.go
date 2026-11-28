package config

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTLSCustomCertificates(t *testing.T) {
	for _, tc := range []struct {
		name string
		tls  string
		want []string
	}{
		{"canonical", `{"custom-certificates":["ca.pem"]}`, []string{"ca.pem"}},
		{"legacy", `{"custom-certifactes":["old.pem"]}`, []string{"old.pem"}},
		{"canonical first", `{"custom-certificates":["ca.pem"],"custom-certifactes":["old.pem"]}`, []string{"ca.pem"}},
		{"legacy first", `{"custom-certifactes":["old.pem"],"custom-certificates":["ca.pem"]}`, []string{"ca.pem"}},
		{"empty overrides legacy", `{"custom-certificates":[],"custom-certifactes":["old.pem"]}`, []string{}},
		{"null overrides legacy", `{"custom-certificates":null,"custom-certifactes":["old.pem"]}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := UnmarshalRawConfig([]byte("tls: " + tc.tls))
			require.NoError(t, err)
			tls, err := parseTLS(raw)
			require.NoError(t, err)
			require.Equal(t, tc.want, tls.CustomTrustCert)

			var rawTLS RawTLS
			require.NoError(t, json.Unmarshal([]byte(tc.tls), &rawTLS))
			require.Equal(t, tc.want, rawTLS.CustomTrustCert)
		})
	}
}
