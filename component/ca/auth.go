package ca

import (
	"github.com/metacubex/tls"
)

type ClientAuthType = tls.ClientAuthType

const (
	NoClientCert               = tls.NoClientCert
	RequestClientCert          = tls.RequestClientCert
	RequireAnyClientCert       = tls.RequireAnyClientCert
	VerifyClientCertIfGiven    = tls.VerifyClientCertIfGiven
	RequireAndVerifyClientCert = tls.RequireAndVerifyClientCert
)

func ClientAuthTypeFromString(s string) ClientAuthType {
	switch s {
	case "request":
		return RequestClientCert
	case "require-any":
		return RequireAnyClientCert
	case "verify-if-given":
		return VerifyClientCertIfGiven
	case "require-and-verify":
		return RequireAndVerifyClientCert
	default:
		return NoClientCert
	}
}

func ClientAuthTypeToString(t ClientAuthType) string {
	switch t {
	case RequestClientCert:
		return "request"
	case RequireAnyClientCert:
		return "require-any"
	case VerifyClientCertIfGiven:
		return "verify-if-given"
	case RequireAndVerifyClientCert:
		return "require-and-verify"
	default:
		return ""
	}
}
