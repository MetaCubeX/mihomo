package net

import (
	"crypto/tls"
	"fmt"
)

func ParseCert(certificate, privateKey string) (tls.Certificate, error) {
	cert, painTextErr := tls.X509KeyPair([]byte(certificate), []byte(privateKey))
	if painTextErr == nil {
		return cert, nil
	}

	cert, loadErr := tls.LoadX509KeyPair(certificate, privateKey)
	if loadErr != nil {
		return tls.Certificate{}, fmt.Errorf("parse certificate failed, maybe format error:%s, or path error: %s", painTextErr.Error(), loadErr.Error())
	}
	return cert, nil
}
