//go:build !s390x

package dns

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	dnscrypt "github.com/ameshkov/dnscrypt/v2"
	"github.com/ameshkov/dnsstamps"
	D "github.com/miekg/dns"
)

// Real public DNS stamps used for offline parsing assertions. These are static
// base64 blobs; no network is touched when they are only parsed.
const (
	// AdGuard DNS default DNSCrypt resolver (proto 0x01).
	dnsCryptStamp = "sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
	// dns.google DoH resolver (proto 0x02) — must be rejected by the DNSCrypt client.
	dohStamp = "sdns://AgUAAAAAAAAAAAAOZG5zLmdvb2dsZS5jb20NL2V4cGVyaW1lbnRhbA"
)

// dotStampString builds a valid DNS-over-TLS stamp so the DoT rejection path can
// be exercised without depending on a memorized base64 blob.
func dotStampString(t *testing.T) string {
	t.Helper()
	stamp := dnsstamps.ServerStamp{
		Proto:         dnsstamps.StampProtoTypeTLS,
		ServerAddrStr: "1.1.1.1:853",
		ProviderName:  "cloudflare-dns.com",
	}
	return stamp.String()
}

func TestNewDNSCryptClient(t *testing.T) {
	tests := []struct {
		name      string
		stamp     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid DNSCrypt stamp",
			stamp:   dnsCryptStamp,
			wantErr: false,
		},
		{
			name:      "DoH stamp is rejected with guidance",
			stamp:     dohStamp,
			wantErr:   true,
			errSubstr: "https://",
		},
		{
			name:      "DoT stamp is rejected with guidance",
			stamp:     dotStampString(t),
			wantErr:   true,
			errSubstr: "tls://",
		},
		{
			name:    "malformed stamp",
			stamp:   "sdns://not-a-valid-stamp",
			wantErr: true,
		},
		{
			name:    "not a stamp at all",
			stamp:   "https://dns.google/dns-query",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := newDNSCryptClient(tt.stamp, nil, nil, nil, "")

			if doc.Address() != tt.stamp {
				t.Errorf("Address() = %q, want %q", doc.Address(), tt.stamp)
			}

			if tt.wantErr {
				if doc.parseErr == nil {
					t.Fatalf("expected a parse error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(doc.parseErr.Error(), tt.errSubstr) {
					t.Errorf("parseErr = %q, want it to contain %q", doc.parseErr.Error(), tt.errSubstr)
				}
				return
			}

			if doc.parseErr != nil {
				t.Fatalf("unexpected parse error: %v", doc.parseErr)
			}
			if doc.stamp.Proto != dnsstamps.StampProtoTypeDNSCrypt {
				t.Errorf("stamp proto = %v, want DNSCrypt", doc.stamp.Proto)
			}
		})
	}
}

// TestDNSCryptExchangeSurfacesParseError verifies the public ExchangeContext
// contract: an unsupported stamp fails fast (before any network I/O) with the
// stashed parse error.
func TestDNSCryptExchangeSurfacesParseError(t *testing.T) {
	doc := newDNSCryptClient(dohStamp, nil, nil, nil, "")

	m := &D.Msg{}
	m.SetQuestion("example.com.", D.TypeA)

	_, err := doc.ExchangeContext(context.Background(), m)
	if err == nil {
		t.Fatal("expected an error for a DoH stamp, got nil")
	}
	if !strings.Contains(err.Error(), "https://") {
		t.Errorf("error = %q, want it to mention the https:// scheme", err.Error())
	}
}

// TestDNSCryptResetConnection verifies that ResetConnection clears the cached
// resolver info so the next query re-fetches the certificate.
func TestDNSCryptResetConnection(t *testing.T) {
	doc := newDNSCryptClient(dnsCryptStamp, nil, nil, nil, "")
	doc.resolverInfo = &dnscrypt.ResolverInfo{} // simulate a cached cert

	doc.ResetConnection()

	if doc.resolverInfo != nil {
		t.Error("ResetConnection did not clear the cached resolver info")
	}
}

// testDNSHandler answers every query with a single, fixed A record.
type testDNSHandler struct{ answerIP net.IP }

func (h testDNSHandler) ServeDNS(rw dnscrypt.ResponseWriter, r *D.Msg) error {
	res := new(D.Msg)
	res.SetReply(r)
	res.Answer = append(res.Answer, &D.A{
		Hdr: D.RR_Header{Name: r.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300},
		A:   h.answerIP,
	})
	return rw.WriteMsg(res)
}

// startLocalDNSCryptServer starts an in-process DNSCrypt resolver on 127.0.0.1
// that answers A queries with answerIP, and returns its sdns:// stamp. The
// server is generated with a fresh cert/keypair and torn down via t.Cleanup, so
// the exchange test stays fully offline and deterministic (CI-safe).
func startLocalDNSCryptServer(t *testing.T, answerIP net.IP) string {
	t.Helper()

	rc, err := dnscrypt.GenerateResolverConfig("2.dnscrypt-cert.example.org", nil)
	if err != nil {
		t.Fatalf("generate resolver config: %v", err)
	}
	cert, err := rc.CreateCert()
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	srv := &dnscrypt.Server{
		ProviderName: rc.ProviderName,
		ResolverCert: cert,
		Handler:      testDNSHandler{answerIP: answerIP},
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	go func() { _ = srv.ServeUDP(conn) }()
	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
		_ = conn.Close()
	})

	stamp, err := rc.CreateStamp(conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("create stamp: %v", err)
	}
	return stamp.String()
}

// TestDNSCryptExchange performs a real DNSCrypt handshake and query against an
// in-process resolver, and checks that the negotiated resolver info is cached
// and reused across queries.
func TestDNSCryptExchange(t *testing.T) {
	answerIP := net.IPv4(203, 0, 113, 7) // TEST-NET-3 sentinel
	stamp := startLocalDNSCryptServer(t, answerIP)

	doc := newDNSCryptClient(stamp, nil, nil, nil, "")
	if doc.parseErr != nil {
		t.Fatalf("unexpected parse error: %v", doc.parseErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	m := &D.Msg{}
	m.SetQuestion("example.com.", D.TypeA)

	resp, err := doc.ExchangeContext(ctx, m)
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if resp.Rcode != D.RcodeSuccess {
		t.Fatalf("unexpected rcode: %s", D.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	if a, ok := resp.Answer[0].(*D.A); !ok || !a.A.Equal(answerIP) {
		t.Fatalf("unexpected answer record: %v", resp.Answer[0])
	}

	// The first exchange must have populated and cached the resolver info.
	cached := doc.resolverInfo
	if cached == nil {
		t.Fatal("resolver info was not cached after the first exchange")
	}

	// A second exchange must reuse the cached resolver info, not re-fetch it.
	if _, err = doc.ExchangeContext(ctx, m); err != nil {
		t.Fatalf("second exchange failed: %v", err)
	}
	if doc.resolverInfo != cached {
		t.Error("resolver info was re-fetched instead of reused from cache")
	}
}
