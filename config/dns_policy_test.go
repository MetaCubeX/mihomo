package config

import (
	"reflect"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	providerTypes "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/dns"
	RP "github.com/metacubex/mihomo/rules/provider"
)

func Test_getMatcher(t *testing.T) {
	type args struct {
		k string
	}
	tests := []struct {
		name  string
		args  args
		want  string
		want1 matcher
	}{
		{
			name:  "rule-set",
			args:  args{k: "rule-set:cn"},
			want:  "cn",
			want1: policyMatcherMap["rule-set"],
		},
		{
			name:  "rule-set",
			args:  args{k: "rULE-set:cn,c2"},
			want:  "cn,c2",
			want1: policyMatcherMap["rule-set"],
		},
		{
			name:  "unknown",
			args:  args{k: "xxx:cn,c2"},
			want:  "xxx:cn,c2",
			want1: nil,
		},
		{
			name:  "domain",
			args:  args{k: "baidu.com"},
			want:  "baidu.com",
			want1: nil,
		},

		{
			name:  "domain list",
			args:  args{k: "baidu.com,+.baidu.com"},
			want:  "baidu.com,+.baidu.com",
			want1: nil,
		},
		{
			name:  "rule",
			args:  args{k: "RuLE:cn,c2"},
			want:  "cn,c2",
			want1: policyMatcherMap["rule"],
		},
		{
			name:  "geosite",
			args:  args{k: "geoSiTe:cn,c2"},
			want:  "cn,c2",
			want1: policyMatcherMap["geosite"],
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := getMatcher(tt.args.k)
			if got != tt.want {
				t.Errorf("getMatcher() got = %v, want %v", got, tt.want)
			}

			if getPointer(got1) != getPointer(tt.want1) {
				t.Errorf("getMatcher() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func getPointer(i any) uintptr {
	return reflect.ValueOf(i).Pointer()
}

func Test_parseDNSPolicy(t *testing.T) {
	type args struct {
		k             string
		nameservers   []dns.NameServer
		ruleProviders map[string]providerTypes.RuleProvider
	}
	ns := []dns.NameServer{
		{
			Net:  "rcode",
			Addr: "success",
		},
	}
	rp := map[string]providerTypes.RuleProvider{
		"cn": RP.NewInlineProvider("cn", providerTypes.Domain,
			[]string{
				"www.baidu.com",
			},
			nil),
	}
	getDomainMatcher := func(str string) C.DomainMatcher {
		m, err := policyMatcherMap["geosite"](str, rp)
		if err != nil {
			t.Error(err)
		}
		return m
	}
	getRuleSetMatcher := func(str string) C.DomainMatcher {
		m, err := policyMatcherMap["rule-set"](str, rp)
		if err != nil {
			t.Error(err)
		}
		return m
	}
	getRuleMatcher := func(str string) C.DomainMatcher {
		m, err := policyMatcherMap["rule"](str, rp)
		if err != nil {
			t.Error(err)
		}
		return m
	}
	tests := []struct {
		name    string
		args    args
		want    []dns.Policy
		wantErr bool
	}{
		{
			name: "未知",
			args: args{
				k:           "xxx:cn",
				nameservers: ns,
			},
			want: []dns.Policy{
				{
					Domain:      "xxx:cn",
					NameServers: ns,
				},
			},
			wantErr: false,
		},
		{
			name: "普通域名",
			args: args{
				k:           "www.baidu.com",
				nameservers: ns,
			},
			want: []dns.Policy{
				{
					Domain:      "www.baidu.com",
					NameServers: ns,
				},
			},
			wantErr: false,
		},
		{
			name: "多个普通域名",
			args: args{
				k:           "www.baidu.com,+.internal.crop.com",
				nameservers: ns,
			},
			want: []dns.Policy{
				{
					Domain:      "www.baidu.com",
					NameServers: ns,
				},
				{
					Domain:      "+.internal.crop.com",
					NameServers: ns,
				},
			},
			wantErr: false,
		},
		{
			name: "geosite 单个",
			args: args{
				k:           "GEoSite:cn",
				nameservers: ns,
			},
			want: []dns.Policy{
				{
					Matcher:     getDomainMatcher("cn"),
					NameServers: ns,
				},
			},
			wantErr: false,
		},
		{
			name: "geosite 多个",
			args: args{
				k:           "GEoSite:cn,category-ads-all",
				nameservers: ns,
			},
			want: []dns.Policy{
				{
					Matcher:     getDomainMatcher("cn"),
					NameServers: ns,
				},
				{
					Matcher:     getDomainMatcher("category-ads-all"),
					NameServers: ns,
				},
			},
			wantErr: false,
		},

		{
			name: "rule-set",
			args: args{
				k:             "RuLe-sEt:cn",
				nameservers:   ns,
				ruleProviders: rp,
			},
			want: []dns.Policy{
				{
					Matcher:     getRuleSetMatcher("cn"),
					NameServers: ns,
				},
			},
			wantErr: false,
		},
		{
			name: "rule",
			args: args{
				k:             "RuLe:direct",
				nameservers:   ns,
				ruleProviders: rp,
			},
			want: []dns.Policy{
				{
					Matcher:     getRuleMatcher("direct"),
					NameServers: ns,
				},
			},
			wantErr: false,
		},
		{
			name: "rule unknown",
			args: args{
				k:             "RuLe:xxxx",
				nameservers:   ns,
				ruleProviders: rp,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDNSPolicy(tt.args.k, tt.args.nameservers, tt.args.ruleProviders)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDNSPolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseDNSPolicy() = %v, want %v", got, tt.want)
			}
		})
	}
}
