package jls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"

	"github.com/metacubex/mihomo/component/ca"
	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/ntp"

	"github.com/metacubex/http"
	"github.com/metacubex/randv2"
	utls "github.com/metacubex/utls"
)

const (
	jlsClientHelloType               = 1
	jlsServerHelloType               = 2
	jlsHandshakeHeaderLen            = 4
	jlsHelloLegacyVersionLen         = 2
	jlsHelloRandomLen                = 32
	jlsHelloRandomOffset             = jlsHandshakeHeaderLen + jlsHelloLegacyVersionLen
	jlsRandomSeedLen                 = jlsHelloRandomLen / 2
	jlsDowngradeCanaryTLS12          = "DOWNGRD\x01"
	jlsDowngradeCanaryTLS11          = "DOWNGRD\x00"
	jlsHelloRetryRequestRandomSuffix = "\x07\x9e\x09\xe2\xc8\xa8\x33\x9c"
)

func newUTLSClient(ctx context.Context, conn net.Conn, config *ClientConfig) (net.Conn, bool, error) {
	fingerprint, ok := tlsC.GetFingerprint(config.ClientFingerprint)
	if !ok {
		return nil, false, nil
	}

	verifier := &utlsJLSVerifier{
		user:       config.User,
		serverName: config.ServerName,
	}
	alpn := config.ALPN
	if alpn == nil {
		alpn = DefaultALPN
	}
	// Resumption would require recalculating PSK binders after replacing the
	// ClientHello random. uTLS does not expose a hook for that operation, so this
	// client deliberately disables session tickets and 0-RTT.
	uConn := utls.UClient(conn, &utls.Config{
		ServerName: config.ServerName,
		NextProtos: append([]string(nil), alpn...),
		// JLS authenticates the server in VerifyConnection. TLS still verifies
		// CertificateVerify against the camouflage certificate's public key.
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		Time:                   ntp.Now,
		VerifyConnection:       verifier.VerifyConnection,
	}, fingerprint)
	verifier.UConn = uConn
	// uTLS has no hook for JLS, so first let it build the complete fingerprint.
	// JLS authenticates the exact serialized ClientHello with random zeroed;
	// changing the random before the fingerprint is finalized would authenticate
	// bytes that can differ from the ClientHello sent on the wire.
	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, true, err
	}
	if config.ALPN != nil {
		overrideUTLSALPN(uConn, config.ALPN)
		if err := uConn.BuildHandshakeState(); err != nil {
			return nil, true, err
		}
	}

	hello := uConn.HandshakeState.Hello
	if !utlsClientHelloSupportsTLS13(hello) {
		return nil, true, errors.New("jls: uTLS fingerprint does not support TLS 1.3")
	}
	authData, err := jlsClientHelloAuthData(hello.Raw)
	if err != nil {
		return nil, true, err
	}
	if len(hello.Random) != jlsHelloRandomLen {
		return nil, true, errors.New("jls: invalid uTLS client random")
	}
	fakeRandom, err := jlsBuildFakeRandom(config.User, hello.Random[:jlsRandomSeedLen], authData, rand.Reader)
	if err != nil {
		return nil, true, err
	}
	if err = uConn.SetClientRandom(fakeRandom); err != nil {
		return nil, true, err
	}
	if err = uConn.BuildHandshakeState(); err != nil {
		return nil, true, err
	}
	verifier.clientHello = append([]byte(nil), uConn.HandshakeState.Hello.Raw...)

	if err = uConn.HandshakeContext(ctx); err != nil {
		return nil, true, err
	}
	if !verifier.authenticated {
		// The fallback certificate is valid, so finish with a plausible HTTP
		// request before returning the JLS authentication error. This is
		// synchronous because the Shadowsocks caller closes conn on return.
		jlsClientHTTPFallback(ctx, uConn, config.ServerName, fingerprint)
		return nil, true, ErrJLSAuthFailed
	}
	if uConn.ConnectionState().Version != utls.VersionTLS13 {
		_ = uConn.Close()
		return nil, true, ErrJLSAuthFailed
	}
	return uConn, true, nil
}

func jlsClientHTTPFallback(ctx context.Context, uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer uConn.Close()
	// The TLS layer is already established, so HTTP/2 must use h2c mode to avoid
	// another TLS handshake. Otherwise use HTTP/1 as negotiated by the server.
	protocols := new(http.Protocols)
	if conn, ok := uConn.(interface{ ConnectionState() utls.ConnectionState }); ok && conn.ConnectionState().NegotiatedProtocol == "h2" {
		protocols.SetUnencryptedHTTP2(true)
	} else {
		protocols.SetHTTP1(true)
	}
	client := http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return uConn, nil
			},
			Protocols: protocols,
		},
	}
	request, err := http.NewRequestWithContext(ctx, "GET", "https://"+serverName, nil)
	if err != nil {
		return
	}
	request.Header.Set("User-Agent", fingerprint.Client)
	request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", randv2.IntN(32)+30)})
	response, err := client.Do(request)
	if err != nil {
		return
	}
	response.Body.Close()
	client.CloseIdleConnections()
}

func utlsClientHelloSupportsTLS13(hello *utls.PubClientHelloMsg) bool {
	for _, version := range hello.SupportedVersions {
		if version == utls.VersionTLS13 {
			return true
		}
	}
	return false
}

type utlsJLSVerifier struct {
	*utls.UConn
	user          User
	serverName    string
	clientHello   []byte
	authenticated bool
}

func (v *utlsJLSVerifier) VerifyConnection(state utls.ConnectionState) error {
	// JLS v3 does not permit HelloRetryRequest at any stage. uTLS replaces
	// HandshakeState.Hello when it sends the second ClientHello.
	if !bytes.Equal(v.clientHello, v.HandshakeState.Hello.Raw) {
		return verifyUTLSCertificate(state, v.serverName)
	}
	serverHello := v.HandshakeState.ServerHello
	if serverHello == nil {
		return errors.New("jls: uTLS server hello is unavailable")
	}
	authData, err := jlsServerHelloAuthData(serverHello.Raw)
	if err != nil {
		return err
	}
	if !jlsCheckFakeRandom(v.user, serverHello.Random, authData) {
		return verifyUTLSCertificate(state, v.serverName)
	}
	v.authenticated = true
	return nil
}

func verifyUTLSCertificate(state utls.ConnectionState, serverName string) error {
	certificates := state.PeerCertificates
	if len(certificates) == 0 {
		return errors.New("jls: fallback server sent no certificates")
	}
	opts := x509.VerifyOptions{
		Roots:         ca.GetCertPool(),
		DNSName:       serverName,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   ntp.Now(),
	}
	for _, certificate := range certificates[1:] {
		opts.Intermediates.AddCert(certificate)
	}
	_, err := certificates[0].Verify(opts)
	return err
}

// overrideUTLSALPN keeps ALPS only when h2 remains advertised.
func overrideUTLSALPN(conn *utls.UConn, protocols []string) {
	hasH2 := false
	for _, protocol := range protocols {
		if protocol == "h2" {
			hasH2 = true
			break
		}
	}

	hasALPN := false
	extensions := conn.Extensions[:0]
	for _, extension := range conn.Extensions {
		switch extension := extension.(type) {
		case *utls.ALPNExtension:
			if len(protocols) == 0 {
				continue
			}
			extension.AlpnProtocols = append([]string(nil), protocols...)
			hasALPN = true
		case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
			if !hasH2 {
				continue
			}
		}
		extensions = append(extensions, extension)
	}
	if !hasALPN && len(protocols) > 0 {
		extensions = append(extensions, &utls.ALPNExtension{
			AlpnProtocols: append([]string(nil), protocols...),
		})
	}
	conn.Extensions = extensions
}

func jlsClientHelloAuthData(raw []byte) ([]byte, error) {
	msg, err := cloneJLSHello(raw, jlsClientHelloType)
	if err != nil {
		return nil, err
	}
	zeroJLSBytes(msg[jlsHelloRandomOffset : jlsHelloRandomOffset+jlsHelloRandomLen])
	return msg, nil
}

func jlsServerHelloAuthData(raw []byte) ([]byte, error) {
	msg, err := cloneJLSHello(raw, jlsServerHelloType)
	if err != nil {
		return nil, err
	}
	zeroJLSBytes(msg[jlsHelloRandomOffset : jlsHelloRandomOffset+jlsHelloRandomLen])
	return msg, nil
}

func cloneJLSHello(raw []byte, messageType byte) ([]byte, error) {
	if len(raw) < jlsHelloRandomOffset+jlsHelloRandomLen ||
		raw[0] != messageType ||
		int(raw[1])<<16|int(raw[2])<<8|int(raw[3]) != len(raw)-jlsHandshakeHeaderLen {
		return nil, errors.New("jls: invalid uTLS hello")
	}
	return append([]byte(nil), raw...), nil
}

func jlsBuildFakeRandom(user User, random16, authData []byte, random io.Reader) ([]byte, error) {
	if len(random16) != jlsRandomSeedLen {
		return nil, errors.New("jls: random seed must be 16 bytes")
	}
	aead, nonce, err := newJLSAEAD(user, authData)
	if err != nil {
		return nil, err
	}
	seed := append([]byte(nil), random16...)
	// JLS v3 reserves the TLS downgrade canaries and the HRR random suffix.
	// Regenerate N instead of emitting a FakeRandom ending in one of them.
	for {
		fakeRandom := aead.Seal(nil, nonce[:], seed, nil)
		if !jlsHasForbiddenRandomSuffix(fakeRandom) {
			return fakeRandom, nil
		}
		if _, err := io.ReadFull(random, seed); err != nil {
			return nil, err
		}
	}
}

func jlsHasForbiddenRandomSuffix(random []byte) bool {
	const suffixLen = len(jlsDowngradeCanaryTLS12)
	if len(random) < suffixLen {
		return false
	}
	suffix := string(random[len(random)-suffixLen:])
	return suffix == jlsDowngradeCanaryTLS12 ||
		suffix == jlsDowngradeCanaryTLS11 ||
		suffix == jlsHelloRetryRequestRandomSuffix
}

func jlsCheckFakeRandom(user User, fakeRandom, authData []byte) bool {
	if len(fakeRandom) != jlsHelloRandomLen {
		return false
	}
	aead, nonce, err := newJLSAEAD(user, authData)
	if err != nil {
		return false
	}
	plain, err := aead.Open(nil, nonce[:], fakeRandom, nil)
	return err == nil && len(plain) == jlsRandomSeedLen
}

func newJLSAEAD(user User, authData []byte) (cipher.AEAD, [sha256.Size]byte, error) {
	nonce := jlsHash(user.Username, authData)
	key := jlsHash(user.Password, authData)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nonce, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	return aead, nonce, err
}

func jlsHash(value string, authData []byte) (sum [sha256.Size]byte) {
	hash := sha256.New()
	_, _ = hash.Write([]byte(value))
	_, _ = hash.Write(authData)
	hash.Sum(sum[:0])
	return sum
}

func zeroJLSBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
