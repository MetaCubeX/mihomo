package config

import (
	"testing"

	"github.com/metacubex/mihomo/common/orderedmap"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMDNSNameServer(t *testing.T) {
	nameservers, err := parseNameServer([]string{"mdns://"}, true, false)
	require.NoError(t, err)
	require.Len(t, nameservers, 1)
	assert.Equal(t, "mdns", nameservers[0].Net)
	assert.Empty(t, nameservers[0].Addr)
	assert.Empty(t, nameservers[0].ProxyName)
}

func TestParseMDNSNameServerPolicy(t *testing.T) {
	rawPolicy := orderedmap.New[string, any]()
	rawPolicy.Set("+.local", []string{"mdns://"})

	policy, err := parseNameServerPolicy(rawPolicy, nil, false, false)
	require.NoError(t, err)
	require.Len(t, policy, 1)
	assert.Equal(t, "+.local", policy[0].Domain)
	require.Len(t, policy[0].NameServers, 1)
	assert.Equal(t, "mdns", policy[0].NameServers[0].Net)
}

func TestParseMDNSNameServerRejectsAddress(t *testing.T) {
	_, err := parseNameServer([]string{"mdns://127.0.0.1"}, false, false)
	assert.ErrorContains(t, err, "does not accept an address or parameters")
}
