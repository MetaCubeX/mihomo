package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"

	"github.com/metacubex/http"
	"github.com/metacubex/randv2"
	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
)

const (
	RealityMaxShortIDLen = 8

	// The REALITY protocol uses Xray-style release bytes as a compatibility
	// gate. These bytes represent Mihomo's tested REALITY compatibility, not
	// Mihomo's application version.
	realityClientVersionMajor byte = 26
	realityClientVersionMinor byte = 7
	realityClientVersionPatch byte = 11
)

type RealityConfig struct {
	PublicKey     *ecdh.PublicKey
	ShortID       [RealityMaxShortIDLen]byte
	Mldsa65Verify []byte
	SpiderX       string
	SpiderY       [10]int64
	Show          bool
	KeyLogWriter  io.Writer
}

func GetRealityConn(ctx context.Context, conn net.Conn, fingerprint UClientHelloID, serverName string, realityConfig *RealityConfig) (net.Conn, error) {
	for retry := 0; ; retry++ {
		verifier := &realityVerifier{
			serverName:    serverName,
			mldsa65Verify: realityConfig.Mldsa65Verify,
			show:          realityConfig.Show,
		}
		uConfig := &utls.Config{
			Time:                   ntp.Now,
			ServerName:             serverName,
			InsecureSkipVerify:     true,
			SessionTicketsDisabled: true,
			VerifyConnection:       verifier.VerifyConnection,
			KeyLogWriter:           realityConfig.KeyLogWriter,
		}

		uConn := utls.UClient(conn, uConfig, fingerprint)
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
		hello.SessionId[0] = realityClientVersionMajor
		hello.SessionId[1] = realityClientVersionMinor
		hello.SessionId[2] = realityClientVersionPatch

		//log.Debugln("REALITY hello.sessionId[:16]: %v", hello.SessionId[:16])

		keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
		if keyShareKeys == nil {
			// WTF???
			if retry > 2 {
				return nil, errors.New("nil keyShareKeys")
			}
			continue // retry
		}
		ecdheKey := keyShareKeys.Ecdhe
		if ecdheKey == nil {
			ecdheKey = keyShareKeys.MlkemEcdhe
		}
		if ecdheKey == nil {
			// WTF???
			if retry > 2 {
				return nil, errors.New("nil ecdheKey")
			}
			continue // retry
		}
		authKey, err := ecdheKey.ECDH(realityConfig.PublicKey)
		if err != nil {
			return nil, err
		}
		if authKey == nil {
			return nil, errors.New("nil auth_key")
		}
		verifier.authKey = authKey
		_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
		if err != nil {
			return nil, err
		}
		aesBlock, _ := aes.NewCipher(authKey)
		aeadCipher, _ := cipher.NewGCM(aesBlock)
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
			go realityClientFallback(uConn, uConfig.ServerName, fingerprint, realityConfig.SpiderX, realityConfig.SpiderY)
			time.Sleep(realityRandomDuration(realityConfig.SpiderY[8], realityConfig.SpiderY[9]))
			return nil, errors.New("REALITY authentication failed")
		}

		return uConn, nil
	}
}

func realityClientFallback(uConn net.Conn, serverName string, fingerprint utls.ClientHelloID, spiderX string, spiderY [10]int64) {
	// use h2c mode to disallow the net/http fallback to http1.1
	//
	// Note that this usage is only applicable to our own net/http fork.
	// The standard library also needs to mask the tls.Conn type for the conn returned by DialTLSContext
	// see: https://github.com/golang/go/issues/79293#issuecomment-4426393534
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	client := http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return uConn, nil
			},
			Protocols: protocols,
		},
	}
	prefix := "https://" + serverName
	realitySpiderPaths.Lock()
	if realitySpiderPaths.paths == nil {
		realitySpiderPaths.paths = make(map[string]map[string]struct{})
	}
	paths := realitySpiderPaths.paths[serverName]
	if paths == nil {
		paths = map[string]struct{}{spiderX: {}}
		realitySpiderPaths.paths[serverName] = paths
	}
	firstURL := prefix + realitySpiderPathLocked(paths)
	realitySpiderPaths.Unlock()

	get := func(first bool) {
		requestURL := firstURL
		if !first {
			realitySpiderPaths.Lock()
			requestURL = prefix + realitySpiderPathLocked(paths)
			realitySpiderPaths.Unlock()
		}
		request, err := http.NewRequest("GET", requestURL, nil)
		if err != nil {
			return
		}
		realitySetNavigationHeaders(request, fingerprint)
		times := int64(1)
		if !first {
			times = realityRandBetween(spiderY[4], spiderY[5])
		}
		for i := int64(0); i < times; i++ {
			if !first && i == 0 {
				request.Header.Set("Referer", firstURL)
			}
			request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", int(realityRandBetween(spiderY[0], spiderY[1])))})
			response, err := client.Do(request)
			if err != nil {
				return
			}
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil {
				return
			}
			request.Header.Set("Referer", request.URL.String())
			realitySpiderPaths.Lock()
			realityDiscoverPaths(paths, prefix, body)
			request.URL.Path = realitySpiderPathLocked(paths)
			realitySpiderPaths.Unlock()
			if !first {
				time.Sleep(realityRandomDuration(spiderY[6], spiderY[7]))
			}
		}
	}

	get(true)
	for i := int64(0); i < realityRandBetween(spiderY[2], spiderY[3]); i++ {
		go get(false)
	}
}

var realityHref = regexp.MustCompile(`href="([/h].*?)"`)

var realitySpiderPaths struct {
	sync.Mutex
	paths map[string]map[string]struct{}
}

func realityDiscoverPaths(paths map[string]struct{}, prefix string, body []byte) {
	for _, match := range realityHref.FindAllSubmatch(body, -1) {
		path := strings.TrimPrefix(string(match[1]), prefix)
		if !strings.Contains(path, ".") {
			paths[path] = struct{}{}
		}
	}
}

func realitySpiderPathLocked(paths map[string]struct{}) string {
	stopAt := randv2.IntN(len(paths))
	index := 0
	for path := range paths {
		if index == stopAt {
			return path
		}
		index++
	}
	return "/"
}

func realityRandBetween(from, to int64) int64 {
	if from == to {
		return from
	}
	if from > to {
		from, to = to, from
	}
	return from + randv2.Int64N(to-from)
}

func realityRandomDuration(from, to int64) time.Duration {
	return time.Duration(realityRandBetween(from, to)) * time.Millisecond
}

func realitySetNavigationHeaders(request *http.Request, _ utls.ClientHelloID) {
	// Xray's default navigation profile is a coherent desktop Chrome request,
	// independently of the uTLS fingerprint selected for the failed handshake.
	const chromeMajor = "148"
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/"+chromeMajor+".0.0.0 Safari/537.36")
	request.Header.Set("Sec-CH-UA", `"Not_A Brand";v="99", "Chromium";v="`+chromeMajor+`", "Google Chrome";v="`+chromeMajor+`"`)
	request.Header.Set("Sec-CH-UA-Mobile", "?0")
	request.Header.Set("Sec-CH-UA-Platform", `"Windows"`)
	request.Header.Set("DNT", "1")
	request.Header.Set("Cache-Control", "max-age=0")
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	request.Header.Set("Accept-Language", "en-US,en;q=0.9")
	request.Header.Set("Sec-Fetch-Dest", "document")
	request.Header.Set("Sec-Fetch-Mode", "navigate")
	request.Header.Set("Sec-Fetch-Site", "none")
	request.Header.Set("Sec-Fetch-User", "?1")
	request.Header.Set("Upgrade-Insecure-Requests", "1")
	request.Header.Set("Priority", "u=0, i")
}

type realityVerifier struct {
	*utls.UConn
	serverName    string
	authKey       []byte
	mldsa65Verify []byte
	verified      bool
	show          bool
}

func (c *realityVerifier) VerifyConnection(state utls.ConnectionState) error {
	if c.show {
		log.Infoln("REALITY localAddr: %v is using X25519MLKEM768 for TLS' communication: %v", c.RemoteAddr(), c.HandshakeState.ServerHello.ServerShare.Group == utls.X25519MLKEM768)
	}
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return errors.New("REALITY server sent no certificate")
	}
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			if c.show {
				log.Infoln("REALITY Ed25519 HMAC certificate authentication: valid")
			}
			if len(c.mldsa65Verify) == 0 {
				c.verified = true
				return nil
			}
			if len(certs[0].Extensions) > 0 {
				h.Write(c.HandshakeState.Hello.Raw)
				h.Write(c.HandshakeState.ServerHello.Raw)
				mldsaValid := utls.RealityMldsa65Verify(c.mldsa65Verify, h.Sum(nil), certs[0].Extensions[0].Value)
				if c.show {
					log.Infoln("REALITY ML-DSA-65 certificate authentication: %v (signature length %d)", mldsaValid, len(certs[0].Extensions[0].Value))
				}
				if mldsaValid {
					c.verified = true
					return nil
				}
			}
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.serverName,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   ntp.Now(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}
