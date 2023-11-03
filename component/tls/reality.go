package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"

	utls "github.com/sagernet/utls"
	"github.com/zhangyunhao116/fastrand"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

const RealityMaxShortIDLen = 8

type RealityConfig struct {
	PublicKey [curve25519.ScalarSize]byte
	ShortID   [RealityMaxShortIDLen]byte
}

//go:linkname aesgcmPreferred crypto/tls.aesgcmPreferred
func aesgcmPreferred(ciphers []uint16) bool

func GetRealityConn(ctx context.Context, conn net.Conn, ClientFingerprint string, tlsConfig *tls.Config, realityConfig *RealityConfig) (net.Conn, error) {
	retry := 0
	for fingerprint, exists := GetFingerprint(ClientFingerprint); exists; retry++ {
		verifier := &realityVerifier{
			serverName: tlsConfig.ServerName,
		}
		uConfig := &utls.Config{
			ServerName:             tlsConfig.ServerName,
			InsecureSkipVerify:     true,
			SessionTicketsDisabled: true,
			VerifyPeerCertificate:  verifier.VerifyPeerCertificate,
		}
		clientID := utls.ClientHelloID{
			Client:  fingerprint.Client,
			Version: fingerprint.Version,
			Seed:    fingerprint.Seed,
		}
		uConn := utls.UClient(conn, uConfig, clientID)
		verifier.UConn = uConn
		err := uConn.BuildHandshakeState()
		if err != nil {
			return nil, err
		}

		hello := uConn.HandshakeState.Hello
		rawSessionID := hello.Raw[39 : 39+32] // the location of session ID
		for i := range rawSessionID {         // https://github.com/golang/go/issues/5373
			rawSessionID[i] = 0
		}

		binary.BigEndian.PutUint64(hello.SessionId, uint64(ntp.Now().Unix()))

		copy(hello.SessionId[8:], realityConfig.ShortID[:])
		hello.SessionId[0] = 1
		hello.SessionId[1] = 8
		hello.SessionId[2] = 2

		//log.Debugln("REALITY hello.sessionId[:16]: %v", hello.SessionId[:16])

		ecdheParams := uConn.HandshakeState.State13.EcdheParams
		if ecdheParams == nil {
			// WTF???
			if retry > 2 {
				return nil, errors.New("nil ecdheParams")
			}
			continue // retry
		}
		authKey := ecdheParams.SharedKey(realityConfig.PublicKey[:])
		if authKey == nil {
			return nil, errors.New("nil auth_key")
		}
		verifier.authKey = authKey
		_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
		if err != nil {
			return nil, err
		}
		var aeadCipher cipher.AEAD
		if aesgcmPreferred(hello.CipherSuites) {
			aesBlock, _ := aes.NewCipher(authKey)
			aeadCipher, _ = cipher.NewGCM(aesBlock)
		} else {
			aeadCipher, _ = chacha20poly1305.New(authKey)
		}
		aeadCipher.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
		copy(hello.Raw[39:], hello.SessionId)
		//log.Debugln("REALITY hello.sessionId: %v", hello.SessionId)
		//log.Debugln("REALITY uConn.AuthKey: %v", authKey)

		err = uConn.HandshakeContext(ctx)
		if err != nil {
			return nil, err
		}

		log.Debugln("REALITY Authentication: %v, AEAD: %T", verifier.verified, aeadCipher)

		if !verifier.verified {
			go realityClientFallback(uConn, uConfig.ServerName, clientID)
			return nil, errors.New("REALITY authentication failed")
		}

		return uConn, nil
	}
	return nil, errors.New("unknown uTLS fingerprint")
}

func realityClientFallback(uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer uConn.Close()
	client := http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
				return uConn, nil
			},
		},
	}
	request, _ := http.NewRequest("GET", "https://"+serverName, nil)
	request.Header.Set("User-Agent", fingerprint.Client)
	request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", fastrand.Intn(32)+30)})
	response, err := client.Do(request)
	if err != nil {
		return
	}
	//_, _ = io.Copy(io.Discard, response.Body)
	time.Sleep(time.Duration(5+fastrand.Int63n(10)) * time.Second)
	response.Body.Close()
	client.CloseIdleConnections()
}

type realityVerifier struct {
	*utls.UConn
	serverName string
	authKey    []byte
	verified   bool
}

var pOffset = utils.MustOK(reflect.TypeOf((*utls.Conn)(nil)).Elem().FieldByName("peerCertificates")).Offset

func (c *realityVerifier) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	//p, _ := reflect.TypeOf(c.Conn).Elem().FieldByName("peerCertificates")
	certs := *(*[]*x509.Certificate)(unsafe.Add(unsafe.Pointer(c.Conn), pOffset))
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.serverName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}
