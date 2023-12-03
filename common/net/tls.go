package net

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
)

type Path interface {
	Resolve(path string) string
}

func ParseCert(certificate, privateKey string, path Path) (tls.Certificate, error) {
	if certificate == "" && privateKey == "" {
		return newRandomTLSKeyPair()
	}
	cert, painTextErr := tls.X509KeyPair([]byte(certificate), []byte(privateKey))
	if painTextErr == nil {
		return cert, nil
	}

	certificate = path.Resolve(certificate)
	privateKey = path.Resolve(privateKey)
	cert, loadErr := tls.LoadX509KeyPair(certificate, privateKey)
	if loadErr != nil {
		return tls.Certificate{}, fmt.Errorf("parse certificate failed, maybe format error:%s, or path error: %s", painTextErr.Error(), loadErr.Error())
	}
	return cert, nil
}

func newRandomTLSKeyPair() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&key.PublicKey,
		key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tlsCert, nil
}
