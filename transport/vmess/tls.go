package vmess

import (
	"context"
	"errors"
	"net"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/transport/jls"
	"github.com/metacubex/mihomo/transport/restls"
	"github.com/metacubex/mihomo/transport/shadowtls"
	"github.com/metacubex/mihomo/transport/tlsmirror"

	"github.com/metacubex/tls"
)

type TLSConfig struct {
	Host              string
	SkipCertVerify    bool
	NameCertVerify    string
	FingerPrint       string
	Certificate       string
	PrivateKey        string
	ClientFingerprint string
	NextProtos        []string
	ECH               *ech.Config
	ShadowTLS         *shadowtls.Config
	Restls            *restls.Config
	JLS               *jls.Config
	Reality           *tlsC.RealityConfig
	TLSMirror         *tlsmirror.Config
	TLSMirrorDialer   tlsmirror.EnrollmentDialer
}

func (cfg *TLSConfig) ToStdConfig() (*tls.Config, error) {
	return ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         cfg.Host,
			InsecureSkipVerify: cfg.SkipCertVerify,
			NextProtos:         cfg.NextProtos,
		},
		Fingerprint:    cfg.FingerPrint,
		NameCertVerify: cfg.NameCertVerify,
		Certificate:    cfg.Certificate,
		PrivateKey:     cfg.PrivateKey,
	})
}

func StreamTLSConn(ctx context.Context, conn net.Conn, cfg *TLSConfig) (net.Conn, error) {
	if cfg.ShadowTLS != nil {
		alpn := cfg.NextProtos
		if alpn == nil {
			alpn = shadowtls.DefaultALPN
		}
		return shadowtls.NewShadowTLS(ctx, conn, &shadowtls.ShadowTLSOption{
			Password:          cfg.ShadowTLS.Password,
			Host:              cfg.Host,
			Fingerprint:       cfg.FingerPrint,
			Certificate:       cfg.Certificate,
			PrivateKey:        cfg.PrivateKey,
			ClientFingerprint: cfg.ClientFingerprint,
			SkipCertVerify:    cfg.SkipCertVerify,
			NameCertVerify:    cfg.NameCertVerify,
			Version:           cfg.ShadowTLS.Version,
			ALPN:              alpn,
		})
	}
	if cfg.Restls != nil {
		restlsConfig := cfg.Restls.Clone()
		restlsConfig.ServerName = cfg.Host
		restlsConfig.NextProtos = cfg.NextProtos
		restlsConfig.InsecureSkipVerify = cfg.SkipCertVerify
		if cfg.FingerPrint != "" {
			if err := restls.SetFingerprint(restlsConfig, cfg.FingerPrint, cfg.NameCertVerify); err != nil {
				return nil, err
			}
		} else if cfg.NameCertVerify != "" {
			restls.SetNameCertVerify(restlsConfig, cfg.NameCertVerify)
		}
		return restls.NewRestls(ctx, conn, restlsConfig)
	}
	if cfg.JLS != nil {
		return jls.NewClient(ctx, conn, &jls.ClientConfig{
			Config:            *cfg.JLS,
			ServerName:        cfg.Host,
			ALPN:              cfg.NextProtos,
			ClientFingerprint: cfg.ClientFingerprint,
		})
	}
	if cfg.TLSMirror != nil {
		return tlsmirror.Dial(ctx, conn, tlsmirror.ClientConfig{
			Config:             *cfg.TLSMirror,
			ServerName:         cfg.Host,
			SkipCertVerify:     cfg.SkipCertVerify,
			NameCertVerify:     cfg.NameCertVerify,
			ALPN:               cfg.NextProtos,
			Fingerprint:        cfg.FingerPrint,
			Certificate:        cfg.Certificate,
			PrivateKey:         cfg.PrivateKey,
			ClientFingerprint:  cfg.ClientFingerprint,
			ForwardAddressHint: cfg.Host,
			ECH:                cfg.ECH,
			EnrollmentDialer:   cfg.TLSMirrorDialer,
		})
	}

	tlsConfig, err := cfg.ToStdConfig()
	if err != nil {
		return nil, err
	}

	clientFingerprintName := cfg.ClientFingerprint
	if cfg.Reality != nil && clientFingerprintName == "" {
		clientFingerprintName = "chrome"
	}
	if clientFingerprint, ok := tlsC.GetFingerprint(clientFingerprintName); ok {
		if cfg.Reality != nil {
			return tlsC.GetRealityConn(ctx, conn, clientFingerprint, tlsConfig.ServerName, cfg.Reality)
		}
		tlsConfig := tlsC.UConfig(tlsConfig)
		err = cfg.ECH.ClientHandleUTLS(ctx, tlsConfig)
		if err != nil {
			return nil, err
		}
		tlsConn := tlsC.UClient(conn, tlsConfig, clientFingerprint)
		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			return nil, err
		}
		return tlsConn, nil
	}
	if cfg.Reality != nil {
		return nil, errors.New("REALITY is based on uTLS, please set a client-fingerprint")
	}

	err = cfg.ECH.ClientHandle(ctx, tlsConfig)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, tlsConfig)

	err = tlsConn.HandshakeContext(ctx)
	return tlsConn, err
}
