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

	"github.com/Dreamacro/clash/common/utils"
	"github.com/Dreamacro/clash/log"

	utls "github.com/sagernet/utls"
	"github.com/zhangyunhao116/fastrand"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

const RealityMaxShortIDLen = 8

type RealityConfig struct {
	PublicKey [curve25519.ScalarSize]byte
	ShortID   [RealityMaxShortIDLen]byte
}

func GetRealityConn(ctx context.Context, conn net.Conn, ClientFingerprint string, tlsConfig *tls.Config, realityConfig *RealityConfig) (net.Conn, error) {
	if fingerprint, exists := GetFingerprint(ClientFingerprint); exists {
		verifier := &realityVerifier{
			serverName: tlsConfig.ServerName,
		}
		uConfig := &utls.Config{
			ServerName:             tlsConfig.ServerName,
			NextProtos:             tlsConfig.NextProtos,
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
		hello.SessionId = make([]byte, 32)
		copy(hello.Raw[39:], hello.SessionId)

		var nowTime time.Time
		if uConfig.Time != nil {
			nowTime = uConfig.Time()
		} else {
			nowTime = time.Now()
		}
		binary.BigEndian.PutUint64(hello.SessionId, uint64(nowTime.Unix()))

		hello.SessionId[0] = 1
		hello.SessionId[1] = 7
		hello.SessionId[2] = 5
		copy(hello.SessionId[8:], realityConfig.ShortID[:])

		//log.Debugln("REALITY hello.sessionId[:16]: %v", hello.SessionId[:16])

		authKey := uConn.HandshakeState.State13.EcdheParams.SharedKey(realityConfig.PublicKey[:])
		if authKey == nil {
			return nil, errors.New("nil auth_key")
		}
		verifier.authKey = authKey
		_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
		if err != nil {
			return nil, err
		}
		aesBlock, _ := aes.NewCipher(authKey)
		aesGcmCipher, _ := cipher.NewGCM(aesBlock)
		aesGcmCipher.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
		copy(hello.Raw[39:], hello.SessionId)
		//log.Debugln("REALITY hello.sessionId: %v", hello.SessionId)
		//log.Debugln("REALITY uConn.AuthKey: %v", authKey)

		err = uConn.HandshakeContext(ctx)
		if err != nil {
			return nil, err
		}

		log.Debugln("REALITY Authentication: %v", verifier.verified)

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
	time.Sleep(time.Duration(5 + fastrand.Int63n(10)))
	response.Body.Close()
	client.CloseIdleConnections()
}

type realityVerifier struct {
	*utls.UConn
	serverName string
	authKey    []byte
	verified   bool
}

var pOffset = utils.MustOK(reflect.TypeOf((*utls.UConn)(nil)).Elem().FieldByName("peerCertificates")).Offset

func (c *realityVerifier) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	//p, _ := reflect.TypeOf(c.Conn).Elem().FieldByName("peerCertificates")
	certs := *(*[]*x509.Certificate)(unsafe.Pointer(uintptr(unsafe.Pointer(c.Conn)) + pOffset))
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
