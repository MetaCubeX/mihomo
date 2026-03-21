// Package masque
// copy and modify from https://github.com/Diniboy1123/usque/blob/d0eb96e7e5c56cce6cf34a7f8d75abbedba58fef/api/masque.go
package masque

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
	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
	"github.com/yosida95/uritemplate/v3"
)

const (
	ConnectSNI = "consumer-masque.cloudflareclient.com"
	ConnectURI = "https://cloudflareaccess.com"
)

// PrepareTlsConfig creates a TLS configuration using the provided certificate and SNI (Server Name Indication).
// It also verifies the peer's public key against the provided public key.
func PrepareTlsConfig(privKey *ecdsa.PrivateKey, peerPubKey *ecdsa.PublicKey, sni string) (*tls.Config, error) {
	verfiyCert := func(cert *x509.Certificate) error {
		if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
			// we only support ECDSA
			// TODO: don't hardcode cert type in the future
			// as backend can start using different cert types
			return x509.ErrUnsupportedAlgorithm
		}

		if !cert.PublicKey.(*ecdsa.PublicKey).Equal(peerPubKey) {
			// reason is incorrect, but the best I could figure
			// detail explains the actual reason

			//10 is NoValidChains, but we support go1.22 where it's not defined
			return x509.CertificateInvalidError{Cert: cert, Reason: 10, Detail: "remote endpoint has a different public key than what we trust"}
		}

		return nil
	}

	cert, err := GenerateCert(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: cert,
				PrivateKey:  privKey,
			},
		},
		ServerName: sni,
		NextProtos: []string{http3.NextProtoH3},
		// WARN: SNI is usually not for the endpoint, so we must skip verification
		InsecureSkipVerify: true,
		// we pin to the endpoint public key
		VerifyConnection: func(cs tls.ConnectionState) error {
			var err error
			for _, cert := range cs.PeerCertificates {
				if er := verfiyCert(cert); er != nil {
					err = errors.Join(err, er)
					continue
				}
			}
			return err
		},
	}

	return tlsConfig, nil
}

func GenerateCert(privKey *ecdsa.PrivateKey) ([][]byte, error) {
	cert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * 24 * time.Hour),
	}, &x509.Certificate{}, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	return [][]byte{cert}, nil
}

// ConnectTunnel establishes a QUIC connection and sets up a Connect-IP tunnel with the provided endpoint.
// Endpoint address is used to check whether the authentication/connection is successful or not.
// Requires modified connect-ip-go for now to support Cloudflare's non RFC compliant implementation.
func ConnectTunnel(ctx context.Context, quicConn *quic.Conn, connectUri string) (*http3.Transport, *connectip.Conn, error) {
	tr := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			// official client still sends this out as well, even though
			// it's deprecated, see https://datatracker.ietf.org/doc/draft-ietf-masque-h3-datagram/00/
			// SETTINGS_H3_DATAGRAM_00 = 0x0000000000000276
			// https://github.com/cloudflare/quiche/blob/7c66757dbc55b8d0c3653d4b345c6785a181f0b7/quiche/src/h3/frame.rs#L46
			0x276: 1,
		},
		DisableCompression: true,
	}

	hconn := tr.NewClientConn(quicConn)

	additionalHeaders := http.Header{
		"User-Agent": []string{""},
	}

	template := uritemplate.MustNew(connectUri)
	ipConn, rsp, err := dialEx(ctx, hconn, template, "cf-connect-ip", additionalHeaders, true)
	if err != nil {
		_ = tr.Close()
		if err.Error() == "CRYPTO_ERROR 0x131 (remote): tls: access denied" {
			return nil, nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
		}
		return nil, nil, fmt.Errorf("failed to dial connect-ip: %v", err)
	}

	err = ipConn.AdvertiseRoute(ctx, []connectip.IPRoute{
		{
			IPProtocol: 0,
			StartIP:    netip.AddrFrom4([4]byte{}),
			EndIP:      netip.AddrFrom4([4]byte{255, 255, 255, 255}),
		},
		{
			IPProtocol: 0,
			StartIP:    netip.AddrFrom16([16]byte{}),
			EndIP: netip.AddrFrom16([16]byte{
				255, 255, 255, 255,
				255, 255, 255, 255,
				255, 255, 255, 255,
				255, 255, 255, 255,
			}),
		},
	})
	if err != nil {
		_ = ipConn.Close()
		_ = tr.Close()
		return nil, nil, err
	}

	if rsp.StatusCode != http.StatusOK {
		_ = ipConn.Close()
		_ = tr.Close()
		return nil, nil, fmt.Errorf("failed to dial connect-ip: %v", rsp.Status)
	}

	return tr, ipConn, nil
}

// dialEx dials a proxied connection to a target server.
func dialEx(ctx context.Context, conn *http3.ClientConn, template *uritemplate.Template, requestProtocol string, additionalHeaders http.Header, ignoreExtendedConnect bool) (*connectip.Conn, *http.Response, error) {
	if len(template.Varnames()) > 0 {
		return nil, nil, errors.New("connect-ip: IP flow forwarding not supported")
	}

	u, err := url.Parse(template.Raw())
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to parse URI: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	case <-conn.Context().Done():
		return nil, nil, context.Cause(conn.Context())
	case <-conn.ReceivedSettings():
	}
	settings := conn.Settings()
	if !ignoreExtendedConnect && !settings.EnableExtendedConnect {
		return nil, nil, errors.New("connect-ip: server didn't enable Extended CONNECT")
	}
	if !settings.EnableDatagrams {
		return nil, nil, errors.New("connect-ip: server didn't enable datagrams")
	}

	const capsuleProtocolHeaderValue = "?1"
	headers := http.Header{http3.CapsuleProtocolHeader: []string{capsuleProtocolHeaderValue}}
	for k, v := range additionalHeaders {
		headers[k] = v
	}

	rstr, err := conn.OpenRequestStream(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to open request stream: %w", err)
	}
	if err := rstr.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  requestProtocol,
		Host:   u.Host,
		Header: headers,
		URL:    u,
	}); err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to send request: %w", err)
	}
	// TODO: optimistically return the connection
	rsp, err := rstr.ReadResponse()
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to read response: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %d", rsp.StatusCode)
	}
	return connectip.NewProxiedConn(rstr), rsp, nil
}
