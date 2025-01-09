package auth

import (
	"github.com/metacubex/mihomo/component/auth"
)

type authStore struct {
	authenticator auth.Authenticator
}

func (a *authStore) Authenticator() auth.Authenticator {
	return a.authenticator
}

func (a *authStore) SetAuthenticator(authenticator auth.Authenticator) {
	a.authenticator = authenticator
}

func NewAuthStore(authenticator auth.Authenticator) auth.AuthStore {
	return &authStore{authenticator}
}

var Default auth.AuthStore = NewAuthStore(nil)

type nilAuthStore struct{}

func (a *nilAuthStore) Authenticator() auth.Authenticator {
	return nil
}

func (a *nilAuthStore) SetAuthenticator(authenticator auth.Authenticator) {}

var Nil auth.AuthStore = (*nilAuthStore)(nil) // always return nil, even call SetAuthenticator() with a non-nil authenticator
