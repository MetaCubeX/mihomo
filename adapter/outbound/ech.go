package outbound

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/mihomo/component/resolver"
)

type ECHOptions struct {
	Enable bool   `proxy:"enable,omitempty" obfs:"enable,omitempty"`
	Config string `proxy:"config,omitempty" obfs:"config,omitempty"`

	QueryServerName string `proxy:"query-server-name,omitempty" obfs:"query-server-name,omitempty"`
}

func (o ECHOptions) Parse() (*ech.Config, error) {
	if !o.Enable {
		return nil, nil
	}
	echConfig := &ech.Config{}
	if o.Config != "" {
		list, err := base64.StdEncoding.DecodeString(o.Config)
		if err != nil {
			return nil, fmt.Errorf("base64 decode ech config string failed: %v", err)
		}
		echConfig.GetEncryptedClientHelloConfigList = func(ctx context.Context, serverName string) ([]byte, error) {
			return list, nil
		}
	} else {
		echConfig.GetEncryptedClientHelloConfigList = func(ctx context.Context, serverName string) ([]byte, error) {
			if o.QueryServerName != "" { // overrides the domain name used for ECH HTTPS record queries
				serverName = o.QueryServerName
			}
			return resolver.ResolveECHWithResolver(ctx, serverName, resolver.ProxyServerHostResolver)
		}
	}
	return echConfig, nil
}
