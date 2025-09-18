package ca

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/metacubex/mihomo/common/once"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"
)

var globalCertPool *x509.CertPool
var mutex sync.RWMutex
var errNotMatch = errors.New("certificate fingerprints do not match")

//go:embed ca-certificates.crt
var _CaCertificates []byte
var DisableEmbedCa, _ = strconv.ParseBool(os.Getenv("DISABLE_EMBED_CA"))
var DisableSystemCa, _ = strconv.ParseBool(os.Getenv("DISABLE_SYSTEM_CA"))

func init() {
	if features.EmbedCaOnly {
		if len(_CaCertificates) == 0 {
			panic("embed_ca_only build tag requires embedded CA certificates")
		}
		DisableEmbedCa = false
		DisableSystemCa = true
	}
}

func AddCertificate(certificate string) error {
	mutex.Lock()
	defer mutex.Unlock()

	if certificate == "" {
		return fmt.Errorf("certificate is empty")
	}

	if globalCertPool == nil {
		initializeCertPool()
	}

	if globalCertPool.AppendCertsFromPEM([]byte(certificate)) {
		return nil
	} else if cert, err := x509.ParseCertificate([]byte(certificate)); err == nil {
		globalCertPool.AddCert(cert)
		return nil
	} else {
		return fmt.Errorf("add certificate failed")
	}
}

func initializeCertPool() {
	var err error
	if DisableSystemCa {
		globalCertPool = x509.NewCertPool()
	} else {
		globalCertPool, err = x509.SystemCertPool()
		if err != nil {
			globalCertPool = x509.NewCertPool()
		}
		log.Debugln("append system CA")
	}
	if !DisableEmbedCa {
		globalCertPool.AppendCertsFromPEM(_CaCertificates)
		log.Debugln("append embed CA")
	}
}

func ResetCertificate() {
	mutex.Lock()
	defer mutex.Unlock()
	initializeCertPool()
}

func GetCertPool(customCA string, customCAString string) (*x509.CertPool, error) {
	var certificate []byte
	var err error
	if len(customCA) > 0 {
		path := C.Path.Resolve(customCA)
		if !C.Path.IsSafePath(path) {
			return nil, C.Path.ErrNotSafePath(path)
		}
		certificate, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("load ca error: %w", err)
		}
	} else if customCAString != "" {
		certificate = []byte(customCAString)
	}
	if len(certificate) > 0 {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(certificate) {
			return nil, fmt.Errorf("failed to parse certificate:\n\n %s", certificate)
		}
		return certPool, nil
	} else {
		mutex.Lock()
		defer mutex.Unlock()
		if globalCertPool == nil {
			initializeCertPool()
		}
		return globalCertPool, nil
	}
}

type Option struct {
	TLSConfig      *tls.Config
	Fingerprint    string
	CustomCA       string
	CustomCAString string
	ZeroTrust      bool
}

func GetTLSConfig(opt Option) (tlsConfig *tls.Config, err error) {
	tlsConfig = opt.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	tlsConfig.Time = ntp.Now

	if opt.ZeroTrust {
		tlsConfig.RootCAs = zeroTrustCertPool()
	} else {
		tlsConfig.RootCAs, err = GetCertPool(opt.CustomCA, opt.CustomCAString)
		if err != nil {
			return nil, err
		}
	}

	if len(opt.Fingerprint) > 0 {
		tlsConfig.VerifyPeerCertificate, err = NewFingerprintVerifier(opt.Fingerprint, tlsConfig.Time)
		if err != nil {
			return nil, err
		}
		tlsConfig.InsecureSkipVerify = true
	}
	return tlsConfig, nil
}

var zeroTrustCertPool = once.OnceValue(func() *x509.CertPool {
	if len(_CaCertificates) != 0 { // always using embed cert first
		zeroTrustCertPool := x509.NewCertPool()
		if zeroTrustCertPool.AppendCertsFromPEM(_CaCertificates) {
			return zeroTrustCertPool
		}
	}
	return nil // fallback to system pool
})
