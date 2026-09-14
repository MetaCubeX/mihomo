package dns

import (
	"context"
	"errors"
	"net"
	"sort"
	"testing"
	"time"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mdnsTestResponder struct {
	network string
	conn    *net.UDPConn
	queries chan *D.Msg
	done    chan struct{}
	handler func(*D.Msg) []*D.Msg
}

func startMDNSTestResponder(t *testing.T, network string, handler func(*D.Msg) []*D.Msg) *mdnsTestResponder {
	t.Helper()

	var listenAddr *net.UDPAddr
	switch network {
	case "udp4":
		listenAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	case "udp6":
		listenAddr = &net.UDPAddr{IP: net.ParseIP("::1")}
	default:
		t.Fatalf("unsupported test network %q", network)
	}
	conn, err := net.ListenUDP(network, listenAddr)
	if err != nil && network == "udp6" {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	require.NoError(t, err)

	responder := &mdnsTestResponder{
		network: network,
		conn:    conn,
		queries: make(chan *D.Msg, 8),
		done:    make(chan struct{}),
		handler: handler,
	}
	go responder.serve()
	t.Cleanup(func() {
		_ = responder.conn.Close()
		<-responder.done
	})
	return responder
}

func (r *mdnsTestResponder) serve() {
	defer close(r.done)
	buffer := make([]byte, mdnsMaxDatagramSize)
	for {
		n, remote, err := r.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		query := &D.Msg{}
		if err = query.Unpack(buffer[:n]); err != nil {
			continue
		}
		select {
		case r.queries <- query.Copy():
		default:
		}
		if r.handler == nil {
			continue
		}
		for _, response := range r.handler(query) {
			wire, err := response.Pack()
			if err != nil {
				continue
			}
			_, _ = r.conn.WriteToUDP(wire, remote)
		}
	}
}

func (r *mdnsTestResponder) target() mdnsTarget {
	addr := *r.conn.LocalAddr().(*net.UDPAddr)
	return mdnsTarget{network: r.network, addr: &addr}
}

func newTestMDNSClient(responder *mdnsTestResponder) *mdnsClient {
	client := newMDNSClient()
	client.timeout = 300 * time.Millisecond
	client.settle = 20 * time.Millisecond
	client.platform = func(context.Context, *D.Msg) (*D.Msg, bool, error) {
		return nil, false, nil
	}
	client.targets = func() ([]mdnsTarget, error) {
		return []mdnsTarget{responder.target()}, nil
	}
	return client
}

func mdnsQuery(name string, qtype uint16) *D.Msg {
	query := &D.Msg{}
	query.SetQuestion(D.Fqdn(name), qtype)
	return query
}

func mdnsReply(query *D.Msg, answers ...D.RR) *D.Msg {
	response := &D.Msg{}
	response.SetReply(query)
	response.Authoritative = true
	// Multicast DNS responses normally omit the Question section.
	response.Question = nil
	response.Answer = answers
	return response
}

func TestMDNSClientAAndAAAA(t *testing.T) {
	tests := []struct {
		name       string
		network    string
		qtype      uint16
		answer     D.RR
		expectedIP string
	}{
		{
			name:       "IPv4A",
			network:    "udp4",
			qtype:      D.TypeA,
			answer:     &D.A{Hdr: D.RR_Header{Name: "printer.local.", Rrtype: D.TypeA, Class: D.ClassINET | mdnsCacheFlush, Ttl: 120}, A: net.IPv4(192, 0, 2, 10)},
			expectedIP: "192.0.2.10",
		},
		{
			name:       "IPv6AAAA",
			network:    "udp6",
			qtype:      D.TypeAAAA,
			answer:     &D.AAAA{Hdr: D.RR_Header{Name: "printer.local.", Rrtype: D.TypeAAAA, Class: D.ClassINET | mdnsCacheFlush, Ttl: 4500}, AAAA: net.ParseIP("2001:db8::10")},
			expectedIP: "2001:db8::10",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			responder := startMDNSTestResponder(t, test.network, func(query *D.Msg) []*D.Msg {
				return []*D.Msg{mdnsReply(query, test.answer)}
			})
			client := newTestMDNSClient(responder)

			response, err := client.ExchangeContext(context.Background(), mdnsQuery("printer.local", test.qtype))
			require.NoError(t, err)
			require.Len(t, response.Answer, 1)
			assert.Equal(t, uint16(D.ClassINET), response.Answer[0].Header().Class)
			assert.Equal(t, test.answer.Header().Ttl, response.Answer[0].Header().Ttl)
			switch answer := response.Answer[0].(type) {
			case *D.A:
				assert.Equal(t, test.expectedIP, answer.A.String())
			case *D.AAAA:
				assert.Equal(t, test.expectedIP, answer.AAAA.String())
			default:
				t.Fatalf("unexpected answer type %T", answer)
			}
		})
	}
}

func TestMDNSClientMergesMultipleResponses(t *testing.T) {
	responder := startMDNSTestResponder(t, "udp4", func(query *D.Msg) []*D.Msg {
		return []*D.Msg{
			mdnsReply(query, &D.A{Hdr: D.RR_Header{Name: "multi.local.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}),
			mdnsReply(query, &D.A{Hdr: D.RR_Header{Name: "multi.local.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 120}, A: net.IPv4(192, 0, 2, 2)}),
		}
	})
	client := newTestMDNSClient(responder)

	response, err := client.ExchangeContext(context.Background(), mdnsQuery("multi.local", D.TypeA))
	require.NoError(t, err)
	require.Len(t, response.Answer, 2)
	ips := []string{response.Answer[0].(*D.A).A.String(), response.Answer[1].(*D.A).A.String()}
	sort.Strings(ips)
	assert.Equal(t, []string{"192.0.2.1", "192.0.2.2"}, ips)
}

func TestMDNSClientTimeout(t *testing.T) {
	responder := startMDNSTestResponder(t, "udp4", nil)
	client := newTestMDNSClient(responder)
	client.timeout = 50 * time.Millisecond

	start := time.Now()
	_, err := client.ExchangeContext(context.Background(), mdnsQuery("silent.local", D.TypeA))
	assert.ErrorIs(t, err, errMDNSTimeout)
	assert.Less(t, time.Since(start), 500*time.Millisecond)
}

func TestMDNSClientContextCancellation(t *testing.T) {
	responder := startMDNSTestResponder(t, "udp4", nil)
	client := newTestMDNSClient(responder)
	client.timeout = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := client.ExchangeContext(ctx, mdnsQuery("cancel.local", D.TypeA))
		result <- err
	}()

	select {
	case <-responder.queries:
	case <-time.After(time.Second):
		t.Fatal("mDNS query was not received")
	}
	cancel()

	select {
	case err := <-result:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("mDNS query did not stop after context cancellation")
	}
}

func TestMDNSClientContextAlreadyCanceled(t *testing.T) {
	client := newMDNSClient()
	client.platform = nil
	client.targets = func() ([]mdnsTarget, error) {
		return nil, errors.New("target discovery should not run")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.ExchangeContext(ctx, mdnsQuery("cancel.local", D.TypeA))
	assert.ErrorIs(t, err, context.Canceled)
}

func TestMDNSClientNoRecords(t *testing.T) {
	responder := startMDNSTestResponder(t, "udp4", func(query *D.Msg) []*D.Msg {
		response := mdnsReply(query)
		response.Ns = []D.RR{&D.NSEC{
			Hdr:        D.RR_Header{Name: "missing.local.", Rrtype: D.TypeNSEC, Class: D.ClassINET | mdnsCacheFlush, Ttl: 120},
			NextDomain: "missing.local.",
			TypeBitMap: []uint16{D.TypeAAAA},
		}}
		return []*D.Msg{response}
	})
	client := newTestMDNSClient(responder)

	response, err := client.ExchangeContext(context.Background(), mdnsQuery("missing.local", D.TypeA))
	require.NoError(t, err)
	assert.Equal(t, D.RcodeSuccess, response.Rcode)
	assert.Empty(t, response.Answer)
	require.Len(t, response.Ns, 1)
	assert.Equal(t, uint16(D.ClassINET), response.Ns[0].Header().Class)
	assert.Equal(t, uint32(120), response.Ns[0].Header().Ttl)
}

func TestMDNSClientEmptyResponseDoesNotProveNoData(t *testing.T) {
	responder := startMDNSTestResponder(t, "udp4", func(query *D.Msg) []*D.Msg {
		return []*D.Msg{mdnsReply(query)}
	})
	client := newTestMDNSClient(responder)
	client.timeout = 50 * time.Millisecond

	_, err := client.ExchangeContext(context.Background(), mdnsQuery("missing.local", D.TypeA))
	assert.ErrorIs(t, err, errMDNSTimeout)
}

func TestMDNSClientCNAMEAcrossPackets(t *testing.T) {
	tests := []struct {
		name          string
		targetFirst   bool
		threePacket   bool
		expectedNames []string
	}{
		{name: "target before CNAME", targetFirst: true, expectedNames: []string{"alias.local.", "target.local."}},
		{name: "CNAME before target", expectedNames: []string{"alias.local.", "target.local."}},
		{name: "three packet chain", threePacket: true, expectedNames: []string{"alias.local.", "middle.local.", "target.local."}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			responder := startMDNSTestResponder(t, "udp4", func(query *D.Msg) []*D.Msg {
				firstCNAME := mdnsReply(query, &D.CNAME{
					Hdr:    D.RR_Header{Name: "alias.local.", Rrtype: D.TypeCNAME, Class: D.ClassINET, Ttl: 120},
					Target: "target.local.",
				})
				targetA := mdnsReply(query, &D.A{
					Hdr: D.RR_Header{Name: "target.local.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
					A:   net.IPv4(192, 0, 2, 40),
				})
				if test.threePacket {
					firstCNAME.Answer[0].(*D.CNAME).Target = "middle.local."
					secondCNAME := mdnsReply(query, &D.CNAME{
						Hdr:    D.RR_Header{Name: "middle.local.", Rrtype: D.TypeCNAME, Class: D.ClassINET, Ttl: 90},
						Target: "target.local.",
					})
					return []*D.Msg{targetA, secondCNAME, firstCNAME}
				}
				if test.targetFirst {
					return []*D.Msg{targetA, firstCNAME}
				}
				return []*D.Msg{firstCNAME, targetA}
			})
			client := newTestMDNSClient(responder)

			response, err := client.ExchangeContext(context.Background(), mdnsQuery("alias.local", D.TypeA))
			require.NoError(t, err)
			require.Len(t, response.Answer, len(test.expectedNames))
			actualNames := make([]string, 0, len(response.Answer))
			for _, answer := range response.Answer {
				actualNames = append(actualNames, answer.Header().Name)
			}
			assert.Equal(t, test.expectedNames, actualNames)
			assert.Equal(t, "192.0.2.40", response.Answer[len(response.Answer)-1].(*D.A).A.String())
		})
	}
}

func TestMergeMDNSResponsesKeepsInterfacesIndependent(t *testing.T) {
	request := mdnsQuery("alias.local", D.TypeA)
	responses := []mdnsResponse{
		{
			ifIndex: 2,
			msg: mdnsReply(request, &D.CNAME{
				Hdr:    D.RR_Header{Name: "alias.local.", Rrtype: D.TypeCNAME, Class: D.ClassINET, Ttl: 120},
				Target: "target.local.",
			}),
		},
		{
			ifIndex: 3,
			msg: mdnsReply(request, &D.A{
				Hdr: D.RR_Header{Name: "target.local.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 50),
			}),
		},
	}

	response, available := mergeMDNSResponses(request, responses)
	assert.False(t, available)
	assert.Empty(t, response.Answer)
}

func TestMergeMDNSResponsesUnionsInterfacesAndMaxTTL(t *testing.T) {
	request := mdnsQuery("host.local", D.TypeA)
	responses := []mdnsResponse{
		{
			ifIndex: 2,
			msg: mdnsReply(request, &D.A{
				Hdr: D.RR_Header{Name: "host.local.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 60),
			}),
		},
		{
			ifIndex: 3,
			msg: mdnsReply(request,
				&D.A{
					Hdr: D.RR_Header{Name: "host.local.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 120},
					A:   net.IPv4(192, 0, 2, 60),
				},
				&D.A{
					Hdr: D.RR_Header{Name: "host.local.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 90},
					A:   net.IPv4(198, 51, 100, 60),
				},
			),
		},
	}

	response, available := mergeMDNSResponses(request, responses)
	require.True(t, available)
	require.Len(t, response.Answer, 2)
	assert.Equal(t, uint32(120), response.Answer[0].Header().Ttl)
	assert.Equal(t, "192.0.2.60", response.Answer[0].(*D.A).A.String())
	assert.Equal(t, "198.51.100.60", response.Answer[1].(*D.A).A.String())
}

func TestValidMDNSTransport(t *testing.T) {
	iface := &net.Interface{Index: 7, Name: "en7"}
	target := mdnsTarget{
		network: "udp4",
		iface:   iface,
		addr:    &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: mdnsPort},
	}
	valid := &mdnsResponse{
		source:      &net.UDPAddr{IP: net.IPv4(192, 0, 2, 70), Port: mdnsPort},
		ifIndex:     iface.Index,
		destination: net.IPv4(224, 0, 0, 251),
		hopLimit:    64,
	}

	// RFC 6762 requires source port 5353 and recommends, but does not require,
	// an IP TTL/hop limit of 255. Retain the latter without rejecting it.
	assert.True(t, validMDNSTransport(valid, target))

	wrongPort := *valid
	wrongPort.source = &net.UDPAddr{IP: valid.source.IP, Port: 12345}
	assert.False(t, validMDNSTransport(&wrongPort, target))

	wrongInterface := *valid
	wrongInterface.ifIndex++
	assert.False(t, validMDNSTransport(&wrongInterface, target))

	wrongDestination := *valid
	wrongDestination.destination = net.IPv4(224, 0, 0, 252)
	assert.False(t, validMDNSTransport(&wrongDestination, target))
}

func TestValidMDNSMessageIgnoresQuestionAndID(t *testing.T) {
	response := mdnsReply(mdnsQuery("host.local", D.TypeA))
	response.Id = 1234
	response.Question = []D.Question{{Name: "other.local.", Qtype: D.TypeAAAA, Qclass: D.ClassINET}}
	assert.True(t, validMDNSMessage(response))

	query := response.Copy()
	query.Response = false
	assert.False(t, validMDNSMessage(query))

	badOpcode := response.Copy()
	badOpcode.Opcode = D.OpcodeStatus
	assert.False(t, validMDNSMessage(badOpcode))

	badRcode := response.Copy()
	badRcode.Rcode = D.RcodeServerFailure
	assert.False(t, validMDNSMessage(badRcode))
}

func TestMDNSClientIgnoresUnrelatedResponseWithoutQuestion(t *testing.T) {
	responder := startMDNSTestResponder(t, "udp4", func(query *D.Msg) []*D.Msg {
		unrelated := mdnsReply(query, &D.A{
			Hdr: D.RR_Header{Name: "other.local.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 30},
			A:   net.IPv4(192, 0, 2, 21),
		})
		unrelated.Question = nil
		expected := mdnsReply(query, &D.A{
			Hdr: D.RR_Header{Name: "wanted.local.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 30},
			A:   net.IPv4(192, 0, 2, 22),
		})
		expected.Question = nil
		return []*D.Msg{unrelated, expected}
	})
	client := newTestMDNSClient(responder)

	response, err := client.ExchangeContext(context.Background(), mdnsQuery("wanted.local", D.TypeA))
	require.NoError(t, err)
	require.Len(t, response.Answer, 1)
	assert.Equal(t, "192.0.2.22", response.Answer[0].(*D.A).A.String())
}

func TestMDNSClientAllowsExplicitNonLocalName(t *testing.T) {
	responder := startMDNSTestResponder(t, "udp4", func(query *D.Msg) []*D.Msg {
		return []*D.Msg{mdnsReply(query, &D.A{
			Hdr: D.RR_Header{Name: "explicit.example.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 30},
			A:   net.IPv4(192, 0, 2, 20),
		})}
	})
	client := newTestMDNSClient(responder)

	response, err := client.ExchangeContext(context.Background(), mdnsQuery("explicit.example", D.TypeA))
	require.NoError(t, err)
	require.Len(t, response.Answer, 1)
	assert.Equal(t, "192.0.2.20", response.Answer[0].(*D.A).A.String())
}

func TestMDNSClientCloseReleasesSockets(t *testing.T) {
	responder := startMDNSTestResponder(t, "udp4", nil)
	client := newTestMDNSClient(responder)
	client.timeout = time.Second
	result := make(chan error, 1)
	go func() {
		_, err := client.ExchangeContext(context.Background(), mdnsQuery("close.local", D.TypeA))
		result <- err
	}()

	select {
	case <-responder.queries:
	case <-time.After(time.Second):
		t.Fatal("mDNS query was not received")
	}
	require.Eventually(t, func() bool { return client.activeSockets() == 1 }, time.Second, 10*time.Millisecond)
	require.NoError(t, client.Close())

	select {
	case err := <-result:
		assert.True(t, errors.Is(err, errMDNSClientClosed) || errors.Is(err, net.ErrClosed), "unexpected error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("mDNS query did not stop after client close")
	}
	assert.Eventually(t, func() bool { return client.activeSockets() == 0 }, time.Second, 10*time.Millisecond)

	_, err := client.ExchangeContext(context.Background(), mdnsQuery("closed.local", D.TypeA))
	assert.ErrorIs(t, err, errMDNSClientClosed)
}

func TestTargetsForMDNSInterfaces(t *testing.T) {
	interfaces := []mdnsInterface{
		{
			iface: net.Interface{Index: 2, Name: "en0", Flags: net.FlagUp | net.FlagMulticast},
			ipv4:  net.IPv4(192, 0, 2, 1),
			ipv6:  net.ParseIP("fe80::1"),
		},
		{
			iface: net.Interface{Index: 3, Name: "en1", Flags: net.FlagUp | net.FlagMulticast},
			ipv4:  net.IPv4(198, 51, 100, 1),
		},
		{
			iface: net.Interface{Index: 4, Name: "down0", Flags: net.FlagMulticast},
			ipv4:  net.IPv4(203, 0, 113, 1),
			ipv6:  net.ParseIP("fe80::2"),
		},
	}

	targets := targetsForMDNSInterfaces(interfaces)
	require.Len(t, targets, 3)
	assert.Equal(t, "udp4", targets[0].network)
	assert.Equal(t, "en0", targets[0].iface.Name)
	assert.Equal(t, "192.0.2.1:0", targets[0].localAddr.String())
	assert.Equal(t, "224.0.0.251:5353", targets[0].addr.String())
	assert.Equal(t, "udp6", targets[1].network)
	assert.Equal(t, "[fe80::1%en0]:0", targets[1].localAddr.String())
	assert.Equal(t, "en0", targets[1].addr.Zone)
	assert.Equal(t, "[ff02::fb%en0]:5353", targets[1].addr.String())
	assert.Equal(t, "udp4", targets[2].network)
	assert.Equal(t, "en1", targets[2].iface.Name)
}

func TestTransformMDNSNameServer(t *testing.T) {
	clients := transform([]NameServer{{Net: "mdns"}}, nil)
	require.Len(t, clients, 1)
	assert.IsType(t, &mdnsClient{}, clients[0])
	assert.Equal(t, "mdns://", clients[0].Address())
}
