//go:build !darwin

package dns

import (
	"context"

	D "github.com/miekg/dns"
)

func (c *mdnsClient) exchangeMDNSPlatform(context.Context, *D.Msg) (*D.Msg, bool, error) {
	return nil, false, nil
}
