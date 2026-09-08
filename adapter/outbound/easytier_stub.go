//go:build no_easytier

package outbound

import "fmt"

type EasyTier struct {
	*Base
}

func NewEasyTier(EasyTierOption) (*EasyTier, error) {
	return nil, fmt.Errorf("EasyTier support is disabled by \"no_easytier\" build tag")
}
