package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/fakeip"
	icontext "github.com/metacubex/mihomo/context"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestWithFakeIPSkipsInvalidDomain(t *testing.T) {
	pool, err := fakeip.New(fakeip.Options{
		IPNet: netip.MustParsePrefix("198.18.0.1/16"),
		Size:  10,
	})
	require.NoError(t, err)

	downstreamCalled := false
	next := func(_ *icontext.DNSContext, request *D.Msg) (*D.Msg, error) {
		downstreamCalled = true
		response := new(D.Msg)
		response.SetReply(request)
		return response, nil
	}

	request := new(D.Msg)
	request.SetQuestion("n-relay-ipc-txc-nj-00.tplinkcloud.com.cn\\152.", D.TypeA)
	response, err := withFakeIP(&fakeip.Skipper{}, pool, nil, 1)(next)(icontext.NewDNSContext(context.Background()), request)

	require.NoError(t, err)
	require.True(t, downstreamCalled)
	require.Empty(t, response.Answer)
	_, mapped := pool.LookBack(netip.MustParseAddr("198.18.0.4"))
	require.False(t, mapped)
}

func TestWithFakeIPKeepsValidDomain(t *testing.T) {
	pool, err := fakeip.New(fakeip.Options{
		IPNet: netip.MustParsePrefix("198.18.0.1/16"),
		Size:  10,
	})
	require.NoError(t, err)

	downstreamCalled := false
	next := func(_ *icontext.DNSContext, request *D.Msg) (*D.Msg, error) {
		downstreamCalled = true
		response := new(D.Msg)
		response.SetReply(request)
		return response, nil
	}

	request := new(D.Msg)
	request.SetQuestion("n-relay-ipc-txc-nj-00.tplinkcloud.com.cn.", D.TypeA)
	dnsCtx := icontext.NewDNSContext(context.Background())
	response, err := withFakeIP(&fakeip.Skipper{}, pool, nil, 1)(next)(dnsCtx, request)

	require.NoError(t, err)
	require.False(t, downstreamCalled)
	require.Len(t, response.Answer, 1)
	require.Equal(t, icontext.DNSTypeFakeIP, dnsCtx.Type())
	host, mapped := pool.LookBack(netip.MustParseAddr("198.18.0.4"))
	require.True(t, mapped)
	require.Equal(t, "n-relay-ipc-txc-nj-00.tplinkcloud.com.cn", host)
}
