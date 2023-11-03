package dialer

import (
	"errors"
)

var (
	ErrorNoIpAddress           = errors.New("no ip address")
	ErrorInvalidedNetworkStack = errors.New("invalided network stack")
)
