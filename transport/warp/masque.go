// Package warp contains Cloudflare WARP's product-specific MASQUE dialect.
// It is intentionally separate from the RFC 9484 implementation in
// transport/masque.
package warp

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"net/url"
	"time"

	connectip "github.com/metacubex/connect-ip-go"
	standard "github.com/metacubex/mihomo/transport/masque"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

const (
	ConnectSNI = "consumer-masque.cloudflareclient.com"
	// The reference client spells this without a trailing slash, but HTTP
	// serializes its empty path as "/". Keep that effective request target
	// explicit so the shared tunnel constructor can validate it.
	ConnectURI = "https://cloudflareaccess.com/"

	requestProtocol       = "cf-connect-ip"
	legacyDatagramSetting = 0x276
)

type IpConn = standard.IpConn

// PrepareTLSConfig creates the self-signed client certificate and server
// public-key pin required by Cloudflare WARP's MASQUE service.
func PrepareTLSConfig(privateKey *ecdsa.PrivateKey, peerPublicKey *ecdsa.PublicKey, sni string, insecure bool) (*tls.Config, error) {
	certificate, err := generateCertificate(privateKey)
	if err != nil {
		return nil, fmt.Errorf("warp: generate client certificate: %w", err)
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: certificate,
			PrivateKey:  privateKey,
		}},
		ServerName:         sni,
		NextProtos:         []string{http3.NextProtoH3},
		InsecureSkipVerify: true, // verified by the key pin below
	}
	if !insecure {
		if peerPublicKey == nil {
			return nil, errors.New("warp: missing MASQUE endpoint public key")
		}
		config.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("warp: endpoint sent no certificate")
			}
			publicKey, ok := state.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return x509.ErrUnsupportedAlgorithm
			}
			if !publicKey.Equal(peerPublicKey) {
				return errors.New("warp: endpoint certificate public key doesn't match the registered key")
			}
			return nil
		}
	}
	return config, nil
}

func generateCertificate(privateKey *ecdsa.PrivateKey) ([][]byte, error) {
	now := time.Now()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
	}, &x509.Certificate{}, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	return [][]byte{der}, nil
}

// ConnectTunnel establishes Cloudflare's HTTP/3 MASQUE dialect. Unlike the
// standard protocol it uses cf-connect-ip, doesn't require the server's
// Extended CONNECT setting, and also emits a legacy H3_DATAGRAM setting.
func ConnectTunnel(ctx context.Context, quicConn *quic.Conn, connectURI string) (*http3.Transport, IpConn, error) {
	tr := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			legacyDatagramSetting: 1,
		},
		DisableCompression: true,
	}
	hconn := tr.NewClientConn(quicConn)
	ipConn, _, err := dialHTTP3(ctx, hconn, connectURI)
	if err != nil {
		_ = tr.Close()
		if stringsContainsAccessDenied(err) {
			return nil, nil, errors.New("warp: MASQUE authentication failed")
		}
		return nil, nil, fmt.Errorf("warp: dial MASQUE over HTTP/3: %w", err)
	}
	if err := advertiseFullTunnel(ctx, ipConn); err != nil {
		_ = ipConn.Close()
		_ = tr.Close()
		return nil, nil, err
	}
	return tr, ipConn, nil
}

func dialHTTP3(ctx context.Context, conn *http3.ClientConn, rawURI string) (*connectip.Conn, *http.Response, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, nil, fmt.Errorf("warp: parse MASQUE URI: %w", err)
	}
	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	case <-conn.Context().Done():
		return nil, nil, context.Cause(conn.Context())
	case <-conn.ReceivedSettings():
	}
	if !conn.Settings().EnableDatagrams {
		return nil, nil, errors.New("warp: server didn't enable HTTP Datagrams")
	}
	rstr, err := conn.OpenRequestStream(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := rstr.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  requestProtocol,
		Host:   u.Host,
		Header: http.Header{
			http3.CapsuleProtocolHeader: []string{standard.CapsuleProtocolHeaderValue},
			"User-Agent":                []string{""},
		},
		URL: u,
	}); err != nil {
		_ = rstr.Close()
		return nil, nil, err
	}
	rsp, err := rstr.ReadResponse()
	if err != nil {
		_ = rstr.Close()
		return nil, nil, err
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		_ = rstr.Close()
		return nil, rsp, fmt.Errorf("server responded with %s", rsp.Status)
	}
	return connectip.NewProxiedConn(rstr), rsp, nil
}

func advertiseFullTunnel(ctx context.Context, conn *connectip.Conn) error {
	return conn.AdvertiseRoute(ctx, []connectip.IPRoute{
		{
			StartIP:    netip.IPv4Unspecified(),
			EndIP:      netip.AddrFrom4([4]byte{255, 255, 255, 255}),
			IPProtocol: 0,
		},
		{
			StartIP:    netip.IPv6Unspecified(),
			EndIP:      netip.AddrFrom16([16]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}),
			IPProtocol: 0,
		},
	})
}

func stringsContainsAccessDenied(err error) bool {
	for current := err; current != nil; current = errors.Unwrap(current) {
		if current.Error() == "CRYPTO_ERROR 0x131 (remote): tls: access denied" {
			return true
		}
	}
	return false
}
