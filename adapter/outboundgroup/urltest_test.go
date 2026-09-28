package outboundgroup

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type urlTestProxy struct {
	C.Proxy
	name  string
	alive bool
	delay uint16
}

func (p *urlTestProxy) Name() string                      { return p.name }
func (p *urlTestProxy) AliveForTestUrl(string) bool       { return p.alive }
func (p *urlTestProxy) LastDelayForTestUrl(string) uint16 { return p.delay }

func TestURLTestFast(t *testing.T) {
	tests := []struct {
		name      string
		proxies   []*urlTestProxy
		selected  string
		previous  string
		tolerance uint16
		want      string
	}{
		{
			name: "skip unhealthy first proxy",
			proxies: []*urlTestProxy{
				{name: "failed", delay: 0},
				{name: "slow", alive: true, delay: 200},
				{name: "fast", alive: true, delay: 100},
			},
			want: "fast",
		},
		{
			name: "all unhealthy fallback",
			proxies: []*urlTestProxy{
				{name: "first"},
				{name: "second"},
			},
			want: "first",
		},
		{
			name: "keep healthy manual selection",
			proxies: []*urlTestProxy{
				{name: "fast", alive: true, delay: 100},
				{name: "selected", alive: true, delay: 200},
			},
			selected: "selected",
			want:     "selected",
		},
		{
			name: "keep previous within tolerance",
			proxies: []*urlTestProxy{
				{name: "failed"},
				{name: "fast", alive: true, delay: 100},
				{name: "previous", alive: true, delay: 120},
			},
			previous:  "previous",
			tolerance: 30,
			want:      "previous",
		},
		{
			name: "replace unhealthy previous proxy",
			proxies: []*urlTestProxy{
				{name: "previous"},
				{name: "healthy", alive: true, delay: 100},
			},
			previous: "previous",
			want:     "healthy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxies := make([]C.Proxy, len(tt.proxies))
			var previous C.Proxy
			for i, proxy := range tt.proxies {
				proxies[i] = proxy
				if proxy.Name() == tt.previous {
					previous = proxy
				}
			}
			u, err := NewURLTest(GroupCommonOption{URL: "https://example.com"}, URLTestOption{Tolerance: tt.tolerance}, proxies[0], nil)
			if err != nil {
				t.Fatal(err)
			}
			u.GroupBase.providerProxies = proxies
			u.selected = tt.selected
			u.fastNode = previous
			if got := u.Now(); got != tt.want {
				t.Fatalf("Now() = %q, want %q", got, tt.want)
			}
		})
	}
}
