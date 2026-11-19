package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseTLSCustomCertificates(t *testing.T) {
	testCases := []struct {
		testName string
		config   string
		expected []string
	}{
		{
			testName: "None",
			config:   "tls: {}\n",
			expected: nil,
		},
		{
			testName: "CorrectSpelling",
			config:   "tls:\n  custom-certificates:\n    - cert-a\n",
			expected: []string{"cert-a"},
		},
		{
			testName: "DeprecatedSpelling",
			config:   "tls:\n  custom-certifactes:\n    - cert-a\n",
			expected: []string{"cert-a"},
		},
		{
			testName: "BothSpellings",
			config:   "tls:\n  custom-certificates:\n    - cert-a\n  custom-certifactes:\n    - cert-b\n",
			expected: []string{"cert-a", "cert-b"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			rawCfg, err := UnmarshalRawConfig([]byte(tc.config))
			assert.NoError(t, err)
			tlsCfg, err := parseTLS(rawCfg)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, tlsCfg.CustomTrustCert)
		})
	}
}
