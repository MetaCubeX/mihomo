package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMultipleProxyListenerType(t *testing.T) {
	cases := []struct {
		name    string
		entry   RawMultipleProxy
		wantT   string
		wantP   int
		wantErr bool
	}{
		{"mixed", RawMultipleProxy{MixedPort: 7890}, "mixed", 7890, false},
		{"http", RawMultipleProxy{Port: 7891}, "http", 7891, false},
		{"socks", RawMultipleProxy{SocksPort: 7892}, "socks", 7892, false},
		{"none", RawMultipleProxy{}, "", 0, true},
		{"two", RawMultipleProxy{MixedPort: 7890, Port: 7891}, "", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ltype, port, err := multipleProxyListenerType(c.entry)
			if c.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, c.wantT, ltype)
			assert.Equal(t, c.wantP, port)
		})
	}
}

func TestValidateMultipleProxyMode(t *testing.T) {
	assert.NoError(t, validateMultipleProxyMode(""))
	assert.NoError(t, validateMultipleProxyMode("global"))
	assert.NoError(t, validateMultipleProxyMode("rule"))
	assert.NoError(t, validateMultipleProxyMode("direct"))
	assert.Error(t, validateMultipleProxyMode("bogus"))
}

func TestCollectUsedPortsRange(t *testing.T) {
	cfg := &RawConfig{
		MixedPort: 7890,
		Listeners: []map[string]any{{"name": "x", "port": "8000-8002"}},
	}
	used, err := collectUsedPorts(cfg)
	assert.NoError(t, err)
	assert.Equal(t, "mixed-port", used[7890])
	assert.Contains(t, used[8000], "listener")
	assert.Contains(t, used[8001], "listener")
	assert.Contains(t, used[8002], "listener")
}
