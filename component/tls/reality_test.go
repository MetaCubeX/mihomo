package tls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
)

func TestRealityChromeClientHelloPreservesFingerprint(t *testing.T) {
	hello, privateKey := captureRealityClientHello(t, utls.HelloChrome_Auto)
	baseline := buildClientHello(t, utls.HelloChrome_Auto)

	assertClientHelloShape(t, baseline, hello)
	if !containsCurve(hello.SupportedCurves, utls.X25519MLKEM768) {
		t.Fatal("Chrome Auto REALITY ClientHello does not contain X25519MLKEM768")
	}
	containsHybridShare := false
	for _, share := range hello.KeyShares {
		if share.Group == utls.X25519MLKEM768 {
			containsHybridShare = true
			break
		}
	}
	if !containsHybridShare {
		t.Fatal("Chrome Auto REALITY ClientHello does not contain an X25519MLKEM768 key share")
	}

	plainSessionID := decryptRealitySessionID(t, hello, privateKey)
	if got, want := [3]byte(plainSessionID[:3]), [3]byte{26, 7, 11}; got != want {
		t.Fatalf("REALITY compatibility version = %v, want %v", got, want)
	}
	if plainSessionID[3] != 0 {
		t.Fatalf("REALITY reserved version byte = %d, want 0", plainSessionID[3])
	}
}

func TestRealityChrome120ClientHelloPreservesLegacyFingerprint(t *testing.T) {
	hello, _ := captureRealityClientHello(t, utls.HelloChrome_120)
	baseline := buildClientHello(t, utls.HelloChrome_120)

	assertClientHelloShape(t, baseline, hello)
	if containsCurve(hello.SupportedCurves, utls.X25519MLKEM768) {
		t.Fatal("Chrome 120 unexpectedly contains X25519MLKEM768")
	}
}

func TestRealityDiscoverPathsMatchesXraySpider(t *testing.T) {
	paths := map[string]struct{}{"/start": {}}
	body := []byte("<a href=\"/next\">next</a>" +
		"<a href=\"https://example.com/absolute\">absolute</a>" +
		"<a href=\"/asset.js\">asset</a>" +
		"<a href=\"https://other.example/page\">other host</a>")
	realityDiscoverPaths(paths, "https://example.com", body)
	for _, want := range []string{"/start", "/next", "/absolute"} {
		if _, ok := paths[want]; !ok {
			t.Fatalf("discovered paths missing %q: %v", want, paths)
		}
	}
	for _, rejected := range []string{"/asset.js", "https://other.example/page"} {
		if _, ok := paths[rejected]; ok {
			t.Fatalf("discovered paths unexpectedly contains %q: %v", rejected, paths)
		}
	}
}

func TestRealityRandBetweenMatchesXrayBounds(t *testing.T) {
	if got := realityRandBetween(7, 7); got != 7 {
		t.Fatalf("equal bounds result = %d, want 7", got)
	}
	for i := 0; i < 100; i++ {
		if got := realityRandBetween(9, 3); got < 3 || got >= 9 {
			t.Fatalf("reversed bounds result = %d, want [3,9)", got)
		}
	}
}

func TestRealityNavigationHeadersMatchXrayChromeProfile(t *testing.T) {
	request, err := http.NewRequest("GET", "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	realitySetNavigationHeaders(request, utls.HelloFirefox_Auto)
	if got := request.Header.Get("User-Agent"); !strings.Contains(got, "Mozilla/5.0") || !strings.Contains(got, "Chrome/") {
		t.Fatalf("User-Agent = %q", got)
	}
	for _, name := range []string{"Sec-CH-UA", "Sec-Fetch-Mode", "Priority", "Upgrade-Insecure-Requests"} {
		if request.Header.Get(name) == "" {
			t.Fatalf("navigation header %q is empty", name)
		}
	}
}

func TestRealityVerifierRequiresConfiguredMldsa65Extension(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authKey := []byte("reality auth key")
	h := hmac.New(sha512.New, authKey)
	_, _ = h.Write(publicKey)
	certificate := &x509.Certificate{PublicKey: publicKey, Signature: h.Sum(nil)}

	withoutMldsa := &realityVerifier{authKey: authKey}
	if err := withoutMldsa.VerifyConnection(utls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}); err != nil {
		t.Fatalf("Ed25519-only verification failed: %v", err)
	}
	if !withoutMldsa.verified {
		t.Fatal("Ed25519-only certificate was not authenticated")
	}

	withMldsa := &realityVerifier{authKey: authKey, mldsa65Verify: make([]byte, 1952)}
	if err := withMldsa.VerifyConnection(utls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}); err == nil {
		t.Fatal("verification accepted a missing ML-DSA-65 extension")
	}
	if withMldsa.verified {
		t.Fatal("missing ML-DSA-65 extension authenticated the certificate")
	}
}

func assertClientHelloShape(t *testing.T, baseline, hello *utls.PubClientHelloMsg) {
	t.Helper()
	assertUint16Shape(t, "cipher suites", baseline.CipherSuites, hello.CipherSuites)
	assertCurveShape(t, "supported curves", baseline.SupportedCurves, hello.SupportedCurves)
	assertKeyShareShape(t, baseline.KeyShares, hello.KeyShares)
	assertUint16Shape(t, "supported versions", baseline.SupportedVersions, hello.SupportedVersions)
	if !reflect.DeepEqual(baseline.SupportedSignatureAlgorithms, hello.SupportedSignatureAlgorithms) {
		t.Fatalf("signature algorithms changed:\nwant %v\n got %v", baseline.SupportedSignatureAlgorithms, hello.SupportedSignatureAlgorithms)
	}
	if !reflect.DeepEqual(baseline.AlpnProtocols, hello.AlpnProtocols) {
		t.Fatalf("ALPN changed:\nwant %v\n got %v", baseline.AlpnProtocols, hello.AlpnProtocols)
	}
	if !reflect.DeepEqual(sortedExtensionIDs(t, baseline.Raw), sortedExtensionIDs(t, hello.Raw)) {
		t.Fatalf("extension set changed:\nwant %v\n got %v", sortedExtensionIDs(t, baseline.Raw), sortedExtensionIDs(t, hello.Raw))
	}
}

func captureRealityClientHello(t *testing.T, fingerprint utls.ClientHelloID) (*utls.PubClientHelloMsg, *ecdh.PrivateKey) {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	deadline := time.Now().Add(5 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)

	result := make(chan error, 1)
	go func() {
		_, err := GetRealityConn(context.Background(), client, fingerprint, "example.com", &RealityConfig{
			PublicKey: privateKey.PublicKey(),
		})
		result <- err
	}()

	hello, err := readClientHello(server)
	if err != nil {
		select {
		case handshakeErr := <-result:
			t.Fatalf("capture ClientHello: %v (handshake: %v)", err, handshakeErr)
		default:
			t.Fatalf("capture ClientHello: %v", err)
		}
	}
	if hello == nil {
		t.Fatal("captured TLS record does not contain a valid ClientHello")
	}
	_ = server.Close()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("REALITY client did not stop after capture connection closed")
	}
	return hello, privateKey
}

func buildClientHello(t *testing.T, fingerprint utls.ClientHelloID) *utls.PubClientHelloMsg {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	uConn := utls.UClient(client, &utls.Config{
		ServerName:             "example.com",
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}, fingerprint)
	if err := uConn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	hello := utls.UnmarshalClientHello(uConn.HandshakeState.Hello.Raw)
	if hello == nil {
		t.Fatal("failed to parse baseline ClientHello")
	}
	return hello
}

func readClientHello(conn net.Conn) (*utls.PubClientHelloMsg, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[3:5]))
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return utls.UnmarshalClientHello(payload), nil
}

func decryptRealitySessionID(t *testing.T, hello *utls.PubClientHelloMsg, privateKey *ecdh.PrivateKey) [16]byte {
	t.Helper()
	var peerPublicKey []byte
	for _, share := range hello.KeyShares {
		if share.Group == utls.X25519 {
			peerPublicKey = share.Data
			break
		}
	}
	if peerPublicKey == nil {
		t.Fatal("captured ClientHello has no X25519 key share")
	}
	peerKey, err := ecdh.X25519().NewPublicKey(peerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	authKey, err := privateKey.ECDH(peerKey)
	if err != nil {
		t.Fatal(err)
	}
	derivedKey := make([]byte, len(authKey))
	if _, err := io.ReadFull(hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")), derivedKey); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	additionalData := append([]byte(nil), hello.Raw...)
	for i := 39; i < 39+32; i++ {
		additionalData[i] = 0
	}
	plain, err := aead.Open(nil, hello.Random[20:], hello.SessionId, additionalData)
	if err != nil {
		t.Fatalf("decrypt REALITY session ID: %v", err)
	}
	return [16]byte(plain)
}

func assertUint16Shape(t *testing.T, name string, want, got []uint16) {
	t.Helper()
	want = normalizeGREASE(want)
	got = normalizeGREASE(got)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("%s changed:\nwant %v\n got %v", name, want, got)
	}
}

func assertCurveShape(t *testing.T, name string, want, got []utls.CurveID) {
	t.Helper()
	w := make([]uint16, len(want))
	g := make([]uint16, len(got))
	for i := range want {
		w[i] = uint16(want[i])
	}
	for i := range got {
		g[i] = uint16(got[i])
	}
	assertUint16Shape(t, name, w, g)
}

func assertKeyShareShape(t *testing.T, want, got []utls.KeyShare) {
	t.Helper()
	w := make([]uint16, len(want))
	g := make([]uint16, len(got))
	for i := range want {
		w[i] = uint16(want[i].Group)
	}
	for i := range got {
		g[i] = uint16(got[i].Group)
	}
	assertUint16Shape(t, "key share groups", w, g)
}

func normalizeGREASE(values []uint16) []uint16 {
	result := append([]uint16(nil), values...)
	for i, value := range result {
		if value&0x0f0f == 0x0a0a && byte(value>>8) == byte(value) {
			result[i] = 0x0a0a
		}
	}
	return result
}

func sortedExtensionIDs(t *testing.T, raw []byte) []uint16 {
	t.Helper()
	offset := 4 + 2 + 32
	offset += 1 + int(raw[offset])
	cipherSuitesLen := int(binary.BigEndian.Uint16(raw[offset : offset+2]))
	offset += 2 + cipherSuitesLen
	offset += 1 + int(raw[offset])
	extensionsLen := int(binary.BigEndian.Uint16(raw[offset : offset+2]))
	offset += 2
	end := offset + extensionsLen
	var ids []uint16
	for offset < end {
		id := binary.BigEndian.Uint16(raw[offset : offset+2])
		length := int(binary.BigEndian.Uint16(raw[offset+2 : offset+4]))
		// Chrome's padding extension is calculated from the final randomized
		// ClientHello length and can legitimately be omitted when no padding is
		// required. It is not a stable part of the fingerprint comparison.
		if id != 21 {
			ids = append(ids, normalizeGREASE([]uint16{id})[0])
		}
		offset += 4 + length
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func containsCurve(curves []utls.CurveID, target utls.CurveID) bool {
	for _, curve := range curves {
		if curve == target {
			return true
		}
	}
	return false
}
