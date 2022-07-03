package acl

import (
	"errors"
	lru "github.com/hashicorp/golang-lru"
	"net"
	"strings"
	"testing"
)

func TestEngine_ResolveAndMatch(t *testing.T) {
	cache, _ := lru.NewARC(16)
	e := &Engine{
		DefaultAction: ActionDirect,
		Entries: []Entry{
			{
				Action:    ActionProxy,
				ActionArg: "",
				Matcher: &domainMatcher{
					matcherBase: matcherBase{
						Protocol: ProtocolTCP,
						Port:     443,
					},
					Domain: "google.com",
					Suffix: false,
				},
			},
			{
				Action:    ActionHijack,
				ActionArg: "good.org",
				Matcher: &domainMatcher{
					matcherBase: matcherBase{},
					Domain:      "evil.corp",
					Suffix:      true,
				},
			},
			{
				Action:    ActionProxy,
				ActionArg: "",
				Matcher: &netMatcher{
					matcherBase: matcherBase{},
					Net: &net.IPNet{
						IP:   net.ParseIP("10.0.0.0"),
						Mask: net.CIDRMask(8, 32),
					},
				},
			},
			{
				Action:    ActionBlock,
				ActionArg: "",
				Matcher:   &allMatcher{},
			},
		},
		Cache: cache,
		ResolveIPAddr: func(s string) (*net.IPAddr, error) {
			if strings.Contains(s, "evil.corp") {
				return nil, errors.New("resolve error")
			}
			return net.ResolveIPAddr("ip", s)
		},
	}
	tests := []struct {
		name       string
		host       string
		port       uint16
		isUDP      bool
		wantAction Action
		wantArg    string
		wantErr    bool
	}{
		{
			name:       "domain proxy",
			host:       "google.com",
			port:       443,
			isUDP:      false,
			wantAction: ActionProxy,
			wantArg:    "",
		},
		{
			name:       "domain block",
			host:       "google.com",
			port:       80,
			isUDP:      false,
			wantAction: ActionBlock,
			wantArg:    "",
		},
		{
			name:       "domain suffix 1",
			host:       "evil.corp",
			port:       8899,
			isUDP:      true,
			wantAction: ActionHijack,
			wantArg:    "good.org",
			wantErr:    true,
		},
		{
			name:       "domain suffix 2",
			host:       "notevil.corp",
			port:       22,
			isUDP:      false,
			wantAction: ActionBlock,
			wantArg:    "",
			wantErr:    true,
		},
		{
			name:       "domain suffix 3",
			host:       "im.real.evil.corp",
			port:       443,
			isUDP:      true,
			wantAction: ActionHijack,
			wantArg:    "good.org",
			wantErr:    true,
		},
		{
			name:       "ip match",
			host:       "10.2.3.4",
			port:       80,
			isUDP:      false,
			wantAction: ActionProxy,
			wantArg:    "",
		},
		{
			name:       "ip mismatch",
			host:       "100.5.6.0",
			port:       1234,
			isUDP:      false,
			wantAction: ActionBlock,
			wantArg:    "",
		},
		{
			name:       "domain proxy cache",
			host:       "google.com",
			port:       443,
			isUDP:      false,
			wantAction: ActionProxy,
			wantArg:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAction, gotArg, _, _, err := e.ResolveAndMatch(tt.host, tt.port, tt.isUDP)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResolveAndMatch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotAction != tt.wantAction {
				t.Errorf("ResolveAndMatch() gotAction = %v, wantAction %v", gotAction, tt.wantAction)
			}
			if gotArg != tt.wantArg {
				t.Errorf("ResolveAndMatch() gotArg = %v, wantAction %v", gotArg, tt.wantArg)
			}
		})
	}
}
