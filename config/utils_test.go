package config

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
)

func TestValidateDialerProxies(t *testing.T) {
	testCases := []struct {
		testName    string
		proxy       []map[string]any
		errContains string
	}{
		{
			testName: "ValidReference",
			proxy: []map[string]any{ // create proxy with valid dialer-proxy reference
				{"name": "base-proxy", "type": "socks5", "server": "127.0.0.1", "port": 1080},
				{"name": "proxy-with-dialer", "type": "socks5", "server": "127.0.0.1", "port": 1081, "dialer-proxy": "base-proxy"},
			},
			errContains: "",
		},
		{
			testName: "NotFoundReference",
			proxy: []map[string]any{ // create proxy with non-existent dialer-proxy reference
				{"name": "proxy-with-dialer", "type": "socks5", "server": "127.0.0.1", "port": 1081, "dialer-proxy": "non-existent-proxy"},
			},
			errContains: "not found",
		},
		{
			testName: "CircularDependency",
			proxy: []map[string]any{
				// create proxy A that references B
				{"name": "proxy-a", "type": "socks5", "server": "127.0.0.1", "port": 1080, "dialer-proxy": "proxy-c"},
				// create proxy B that references C
				{"name": "proxy-b", "type": "socks5", "server": "127.0.0.1", "port": 1081, "dialer-proxy": "proxy-a"},
				// create proxy C that references A (creates cycle)
				{"name": "proxy-c", "type": "socks5", "server": "127.0.0.1", "port": 1082, "dialer-proxy": "proxy-a"},
			},
			errContains: "circular",
		},
		{
			testName: "ComplexChain",
			proxy: []map[string]any{ // create a valid chain: proxy-d -> proxy-c -> proxy-b -> proxy-a
				{"name": "proxy-a", "type": "socks5", "server": "127.0.0.1", "port": 1080},
				{"name": "proxy-b", "type": "socks5", "server": "127.0.0.1", "port": 1081, "dialer-proxy": "proxy-a"},
				{"name": "proxy-c", "type": "socks5", "server": "127.0.0.1", "port": 1082, "dialer-proxy": "proxy-b"},
				{"name": "proxy-d", "type": "socks5", "server": "127.0.0.1", "port": 1083, "dialer-proxy": "proxy-c"},
			},
			errContains: "",
		},
		{
			testName: "EmptyDialerProxy",
			proxy: []map[string]any{ // create proxy without dialer-proxy
				{"name": "simple-proxy", "type": "socks5", "server": "127.0.0.1", "port": 1080},
			},
			errContains: "",
		},
		{
			testName: "SelfReference",
			proxy: []map[string]any{ // create proxy that references itself
				{"name": "self-proxy", "type": "socks5", "server": "127.0.0.1", "port": 1080, "dialer-proxy": "self-proxy"},
			},
			errContains: "circular",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			config := RawConfig{Proxy: testCase.proxy}
			_, _, err := parseProxies(&config)
			if testCase.errContains == "" {
				assert.NoError(t, err, testCase.testName)
			} else {
				assert.ErrorContains(t, err, testCase.errContains, testCase.testName)
			}
		})
	}
}

// newDialerTestProxies builds a socks5 proxy for each name, with the given dialer-proxy ("" for none).
func newDialerTestProxies(t *testing.T, dialerProxies map[string]string) map[string]C.Proxy {
	t.Helper()
	proxies := make(map[string]C.Proxy, len(dialerProxies))
	for name, dialerProxy := range dialerProxies {
		socks5, err := outbound.NewSocks5(outbound.Socks5Option{
			BasicOption: outbound.BasicOption{DialerProxy: dialerProxy},
			Name:        name,
			Server:      "127.0.0.1",
			Port:        1080,
		})
		if err != nil {
			t.Fatal(err)
		}
		proxies[name] = adapter.NewProxy(socks5)
	}
	return proxies
}

func TestValidateDialerProxiesCycles(t *testing.T) {
	testCases := []struct {
		testName      string
		dialerProxies map[string]string
		// the proxy named in a cycle error depends on map iteration order,
		// so any of these errors is accepted; nil means no error
		errs []string
	}{
		{
			testName:      "NoDialerProxy",
			dialerProxies: map[string]string{"a": "", "b": ""},
		},
		{
			testName:      "Chains",
			dialerProxies: map[string]string{"a": "b", "b": "c", "c": "", "d": "c", "e": "c"},
		},
		{
			testName:      "NotFound",
			dialerProxies: map[string]string{"a": "b", "b": "", "c": "missing"},
			errs:          []string{"proxy [c] dialer-proxy [missing] not found"},
		},
		{
			testName:      "NotFoundBeforeCycle",
			dialerProxies: map[string]string{"a": "b", "b": "a", "c": "missing"},
			errs:          []string{"proxy [c] dialer-proxy [missing] not found"},
		},
		{
			testName:      "SelfReference",
			dialerProxies: map[string]string{"a": "", "self": "self"},
			errs:          []string{"proxy [self] has circular dialer-proxy dependency"},
		},
		{
			testName:      "TwoProxyCycle",
			dialerProxies: map[string]string{"a": "b", "b": "a", "c": ""},
			errs: []string{
				"proxy [a] has circular dialer-proxy dependency",
				"proxy [b] has circular dialer-proxy dependency",
			},
		},
		{
			testName: "LongChainIntoCycle",
			// x -> a -> b -> c -> d -> e -> c, beside an acyclic chain y -> z, w -> z
			dialerProxies: map[string]string{"x": "a", "a": "b", "b": "c", "c": "d", "d": "e", "e": "c", "y": "z", "z": "", "w": "z"},
			errs: []string{
				"proxy [x] has circular dialer-proxy dependency",
				"proxy [a] has circular dialer-proxy dependency",
				"proxy [b] has circular dialer-proxy dependency",
				"proxy [c] has circular dialer-proxy dependency",
				"proxy [d] has circular dialer-proxy dependency",
				"proxy [e] has circular dialer-proxy dependency",
			},
		},
		{
			testName: "SharedRelayBesideCycle",
			// p and q share an acyclic relay, t leads into the cycle r <-> s
			dialerProxies: map[string]string{"p": "relay", "q": "relay", "relay": "", "r": "s", "s": "r", "t": "s"},
			errs: []string{
				"proxy [r] has circular dialer-proxy dependency",
				"proxy [s] has circular dialer-proxy dependency",
				"proxy [t] has circular dialer-proxy dependency",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			proxies := newDialerTestProxies(t, testCase.dialerProxies)
			// repeat so that different map iteration orders are covered
			for i := 0; i < 20; i++ {
				err := validateDialerProxies(proxies)
				if testCase.errs == nil {
					assert.NoError(t, err)
				} else if assert.Error(t, err) {
					assert.Contains(t, testCase.errs, err.Error())
				}
			}
		})
	}
}

// The check must cost in proportion to the number of proxies: four times the
// proxies may allocate at most twice what linear growth allows, while a check
// that is quadratic in the number of proxies allocates sixteen times as much.
func TestValidateDialerProxiesLinearCost(t *testing.T) {
	const small, large = 250, 1000
	shapes := []struct {
		testName    string
		dialerProxy func(i int) string
	}{
		{"SharedRelay", func(int) string { return "relay" }},
		{"LongChain", func(i int) string {
			if i == 0 {
				return "relay"
			}
			return fmt.Sprintf("proxy-%d", i-1)
		}},
	}

	for _, shape := range shapes {
		t.Run(shape.testName, func(t *testing.T) {
			allocated := func(n int) uint64 {
				dialerProxies := map[string]string{"relay": ""}
				for i := 0; i < n; i++ {
					dialerProxies[fmt.Sprintf("proxy-%d", i)] = shape.dialerProxy(i)
				}
				proxies := newDialerTestProxies(t, dialerProxies)
				var least uint64
				for i := 0; i < 3; i++ {
					var before, after runtime.MemStats
					runtime.ReadMemStats(&before)
					if err := validateDialerProxies(proxies); err != nil {
						t.Fatal(err)
					}
					runtime.ReadMemStats(&after)
					if bytes := after.TotalAlloc - before.TotalAlloc; i == 0 || bytes < least {
						least = bytes
					}
				}
				return least
			}
			smallBytes, largeBytes := allocated(small), allocated(large)
			if largeBytes > 2*(large/small)*smallBytes {
				t.Fatalf("%d proxies allocated %d bytes, %d proxies allocated %d bytes", small, smallBytes, large, largeBytes)
			}
		})
	}
}
