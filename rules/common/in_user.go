package common

import (
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
)

type InUser struct {
	Base
	users   []string
	adapter string
	payload string
}

func (u *InUser) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	for _, user := range u.users {
		if metadata.InUser == user {
			return true, u.adapter
		}
	}
	return false, ""
}

func (u *InUser) RuleType() C.RuleType {
	return C.InUser
}

func (u *InUser) Adapter() string {
	return u.adapter
}

func (u *InUser) Payload() string {
	return u.payload
}

func NewInUser(iUsers, adapter string) (*InUser, error) {
	users := strings.Split(iUsers, "/")
	for i, user := range users {
		user = strings.TrimSpace(user)
		if len(user) == 0 {
			return nil, fmt.Errorf("in user couldn't be empty")
		}
		users[i] = user
	}

	return &InUser{
		Base:    Base{},
		users:   users,
		adapter: adapter,
		payload: iUsers,
	}, nil
}

var _ C.Rule = (*InUser)(nil)
