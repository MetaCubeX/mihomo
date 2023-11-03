package common

import (
	"fmt"
	C "github.com/metacubex/mihomo/constant"
	"strings"
)

type InUser struct {
	*Base
	users   []string
	adapter string
	payload string
}

func (u *InUser) Match(metadata *C.Metadata) (bool, string) {
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
	if len(users) == 0 {
		return nil, fmt.Errorf("in user couldn't be empty")
	}

	return &InUser{
		Base:    &Base{},
		users:   users,
		adapter: adapter,
		payload: iUsers,
	}, nil
}
