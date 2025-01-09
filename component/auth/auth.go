package auth

type Authenticator interface {
	Verify(user string, pass string) bool
	Users() []string
}

type AuthStore interface {
	Authenticator() Authenticator
	SetAuthenticator(Authenticator)
}

type AuthUser struct {
	User string
	Pass string
}

type inMemoryAuthenticator struct {
	storage   map[string]string
	usernames []string
}

func (au *inMemoryAuthenticator) Verify(user string, pass string) bool {
	realPass, ok := au.storage[user]
	return ok && realPass == pass
}

func (au *inMemoryAuthenticator) Users() []string { return au.usernames }

func NewAuthenticator(users []AuthUser) Authenticator {
	if len(users) == 0 {
		return nil
	}
	au := &inMemoryAuthenticator{
		storage:   make(map[string]string),
		usernames: make([]string, 0, len(users)),
	}
	for _, user := range users {
		au.storage[user.User] = user.Pass
		au.usernames = append(au.usernames, user.User)
	}
	return au
}
