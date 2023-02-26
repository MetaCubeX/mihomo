package dialer

import (
	"errors"

	E "github.com/sagernet/sing/common/exceptions"
)

var (
	ErrorNoIpAddress           = errors.New("no ip address")
	ErrorInvalidedNetworkStack = errors.New("invalided network stack")
)

func errorsJoin(errs ...error) error {
	// compatibility with golang<1.20
	// maybe use errors.Join(errs...) is better after we drop the old version's support
	return E.Errors(errs...)
}
