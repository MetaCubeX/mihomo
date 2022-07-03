package acl

import (
	"net"
	"reflect"
	"testing"
)

func TestParseEntry(t *testing.T) {
	_, ok3net, _ := net.ParseCIDR("8.8.8.0/24")

	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    Entry
		wantErr bool
	}{
		{name: "empty", args: args{""}, want: Entry{}, wantErr: true},
		{name: "ok 1", args: args{"direct domain-suffix google.com"},
			want: Entry{ActionDirect, "", &domainMatcher{
				matcherBase: matcherBase{},
				Domain:      "google.com",
				Suffix:      true,
			}},
			wantErr: false},
		{name: "ok 2", args: args{"proxy domain shithole"},
			want: Entry{ActionProxy, "", &domainMatcher{
				matcherBase: matcherBase{},
				Domain:      "shithole",
				Suffix:      false,
			}},
			wantErr: false},
		{name: "ok 3", args: args{"block cidr 8.8.8.0/24 */53"},
			want: Entry{ActionBlock, "", &netMatcher{
				matcherBase: matcherBase{ProtocolAll, 53},
				Net:         ok3net,
			}},
			wantErr: false},
		{name: "ok 4", args: args{"hijack all udp/* udpblackhole.net"},
			want: Entry{ActionHijack, "udpblackhole.net", &allMatcher{
				matcherBase: matcherBase{ProtocolUDP, 0},
			}},
			wantErr: false},
		{name: "err 1", args: args{"what the heck"},
			want:    Entry{},
			wantErr: true},
		{name: "err 2", args: args{"proxy sucks ass"},
			want:    Entry{},
			wantErr: true},
		{name: "err 3", args: args{"block ip 999.999.999.999"},
			want:    Entry{},
			wantErr: true},
		{name: "err 4", args: args{"hijack domain google.com"},
			want:    Entry{},
			wantErr: true},
		{name: "err 5", args: args{"hijack domain google.com bing.com 123"},
			want:    Entry{},
			wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEntry(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseEntry() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseEntry() got = %v, wantAction %v", got, tt.want)
			}
		})
	}
}
