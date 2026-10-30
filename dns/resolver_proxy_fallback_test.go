package dns

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/component/trie"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type proxyFallbackTestClient struct {
	address string
	ip      string
	err     error
	calls   atomic.Int32
}

func (c *proxyFallbackTestClient) ExchangeContext(ctx context.Context, query *D.Msg) (*D.Msg, error) {
	c.calls.Add(1)
	if c.err != nil {
		return nil, c.err
	}

	msg := &D.Msg{}
	msg.SetReply(query)
	msg.Answer = []D.RR{&D.A{
		Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
		A:   net.ParseIP(c.ip).To4(),
	}}
	return msg, nil
}

func (c *proxyFallbackTestClient) Address() string  { return c.address }
func (c *proxyFallbackTestClient) ResetConnection() {}

func proxyFallbackPolicy(t *testing.T, domain string, clients []dnsClient) dnsPolicy {
	t.Helper()
	policyTrie := trie.New[[]dnsClient]()
	require.NoError(t, policyTrie.Insert(domain, clients))
	policyTrie.Optimize()
	return domainTriePolicy{policyTrie}
}

func TestProxyServerNameserverFallback(t *testing.T) {
	primary := &proxyFallbackTestClient{address: "primary", err: errors.New("primary unavailable")}
	fallback := &proxyFallbackTestClient{address: "fallback", ip: "192.0.2.1"}
	r := &Resolver{
		main:     []dnsClient{primary},
		fallback: []dnsClient{fallback},
		cache:    Config{}.newCache(),
	}

	ips, err := r.LookupIPv4(context.Background(), "node.example.com")
	require.NoError(t, err)
	require.Len(t, ips, 1)
	assert.Equal(t, "192.0.2.1", ips[0].String())
	assert.Equal(t, int32(1), primary.calls.Load())
	assert.Equal(t, int32(1), fallback.calls.Load())
}

func TestProxyServerNameserverKeepsPrimaryResult(t *testing.T) {
	primary := &proxyFallbackTestClient{address: "primary", ip: "192.0.2.2"}
	fallback := &proxyFallbackTestClient{address: "fallback", ip: "192.0.2.1"}
	r := &Resolver{
		main:              []dnsClient{primary},
		fallback:          []dnsClient{fallback},
		fallbackLazyQuery: true,
		cache:             Config{}.newCache(),
	}

	ips, err := r.LookupIPv4(context.Background(), "node.example.com")
	require.NoError(t, err)
	require.Len(t, ips, 1)
	assert.Equal(t, "192.0.2.2", ips[0].String())
	assert.Equal(t, int32(0), fallback.calls.Load())
}

func TestProxyServerPolicyFallback(t *testing.T) {
	main := &proxyFallbackTestClient{address: "main", ip: "192.0.2.1"}
	policy := &proxyFallbackTestClient{address: "policy", err: errors.New("policy unavailable")}
	fallback := &proxyFallbackTestClient{address: "policy-fallback", ip: "192.0.2.3"}
	r := &Resolver{
		main:           []dnsClient{main},
		policy:         []dnsPolicy{proxyFallbackPolicy(t, "node.example.com", []dnsClient{policy})},
		policyFallback: []dnsPolicy{proxyFallbackPolicy(t, "node.example.com", []dnsClient{fallback})},
		cache:          Config{}.newCache(),
	}

	ips, err := r.LookupIPv4(context.Background(), "node.example.com")
	require.NoError(t, err)
	require.Len(t, ips, 1)
	assert.Equal(t, "192.0.2.3", ips[0].String())
	assert.Equal(t, int32(0), main.calls.Load())
	assert.Equal(t, int32(1), policy.calls.Load())
	assert.Equal(t, int32(1), fallback.calls.Load())
}

func TestProxyServerPolicyKeepsPrimaryResult(t *testing.T) {
	policy := &proxyFallbackTestClient{address: "policy", ip: "192.0.2.4"}
	fallback := &proxyFallbackTestClient{address: "policy-fallback", ip: "192.0.2.3"}
	r := &Resolver{
		main:              []dnsClient{fallback},
		policy:            []dnsPolicy{proxyFallbackPolicy(t, "node.example.com", []dnsClient{policy})},
		policyFallback:    []dnsPolicy{proxyFallbackPolicy(t, "node.example.com", []dnsClient{fallback})},
		fallbackLazyQuery: true,
		cache:             Config{}.newCache(),
	}

	ips, err := r.LookupIPv4(context.Background(), "node.example.com")
	require.NoError(t, err)
	require.Len(t, ips, 1)
	assert.Equal(t, "192.0.2.4", ips[0].String())
	assert.Equal(t, int32(0), fallback.calls.Load())
}
