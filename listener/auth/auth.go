package auth

import (
	"github.com/metacubex/mihomo/component/auth"
)

var authenticator auth.Authenticator
var authenticatorTls auth.Authenticator

func Authenticator() auth.Authenticator {
	return authenticator
}
func AuthenticatorTls() auth.Authenticator {
	return authenticatorTls
}
func SetAuthenticator(au auth.Authenticator) {
	authenticator = au
}
func SetAuthenticatorTls(au auth.Authenticator) {
	authenticatorTls = au
}
