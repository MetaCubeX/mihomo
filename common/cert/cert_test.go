package cert

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCert(t *testing.T) {
	ca, privateKey, err := NewAuthority("Clash ca", "Clash", 24*time.Hour)

	assert.Nil(t, err)
	assert.NotNil(t, ca)
	assert.NotNil(t, privateKey)

	c, err := NewConfig(ca, privateKey)
	assert.Nil(t, err)

	c.SetValidity(20 * time.Hour)
	c.SetOrganization("Test Organization")

	conf := c.NewTLSConfigForHost("example.org")
	assert.Equal(t, []string{"http/1.1"}, conf.NextProtos)
	assert.True(t, conf.InsecureSkipVerify)

	// Test generating a certificate
	clientHello := &tls.ClientHelloInfo{
		ServerName: "example.org",
	}
	tlsCert, err := conf.GetCertificate(clientHello)
	assert.Nil(t, err)
	assert.NotNil(t, tlsCert)

	// Assert certificate details
	x509c := tlsCert.Leaf
	assert.Equal(t, "example.org", x509c.Subject.CommonName)
	assert.Nil(t, x509c.VerifyHostname("example.org"))
	assert.Nil(t, x509c.VerifyHostname("abc.example.org"))
	assert.Equal(t, []string{"Test Organization"}, x509c.Subject.Organization)
	assert.NotNil(t, x509c.SubjectKeyId)
	assert.True(t, x509c.BasicConstraintsValid)
	assert.True(t, x509c.KeyUsage&x509.KeyUsageKeyEncipherment == x509.KeyUsageKeyEncipherment)
	assert.True(t, x509c.KeyUsage&x509.KeyUsageDigitalSignature == x509.KeyUsageDigitalSignature)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, x509c.ExtKeyUsage)
	assert.Equal(t, []string{"example.org", "*.example.org"}, x509c.DNSNames)
	assert.True(t, x509c.NotBefore.Before(time.Now().Add(-2*time.Hour)))
	assert.True(t, x509c.NotAfter.After(time.Now().Add(2*time.Hour)))

	// Check that certificate is cached
	tlsCert2, err := c.GetOrCreateCert("abc.example.org")
	assert.Nil(t, err)
	assert.True(t, tlsCert == tlsCert2)

	// Check that certificate is new
	_, _ = c.GetOrCreateCert("a.b.c.d.e.f.g.h.i.j.example.org")
	tlsCert3, err := c.GetOrCreateCert("m.k.l.example.org")
	x509c = tlsCert3.Leaf
	assert.Nil(t, err)
	assert.False(t, tlsCert == tlsCert3)
	assert.Equal(t, []string{"example.org", "*.example.org", "*.j.example.org", "*.i.j.example.org", "*.h.i.j.example.org", "*.g.h.i.j.example.org", "*.f.g.h.i.j.example.org", "*.e.f.g.h.i.j.example.org", "*.d.e.f.g.h.i.j.example.org", "*.c.d.e.f.g.h.i.j.example.org", "*.b.c.d.e.f.g.h.i.j.example.org", "*.l.example.org", "*.k.l.example.org"}, x509c.DNSNames)

	// Check that certificate is cached
	tlsCert4, err := c.GetOrCreateCert("xyz.example.org")
	x509c = tlsCert4.Leaf
	assert.Nil(t, err)
	assert.True(t, tlsCert3 == tlsCert4)
	assert.Nil(t, x509c.VerifyHostname("example.org"))
	assert.Nil(t, x509c.VerifyHostname("jkf.example.org"))
	assert.Nil(t, x509c.VerifyHostname("n.j.example.org"))
	assert.Nil(t, x509c.VerifyHostname("c.i.j.example.org"))
	assert.Nil(t, x509c.VerifyHostname("m.l.example.org"))
	assert.Error(t, x509c.VerifyHostname("m.l.jkf.example.org"))

	// Check the certificate for an IP
	tlsCertForIP, err := c.GetOrCreateCert("192.168.0.1")
	x509c = tlsCertForIP.Leaf
	assert.Nil(t, err)
	assert.Equal(t, 1, len(x509c.IPAddresses))
	assert.True(t, net.ParseIP("192.168.0.1").Equal(x509c.IPAddresses[0]))

	// Check that certificate is cached
	tlsCertForIP2, err := c.GetOrCreateCert("192.168.0.1")
	x509c = tlsCertForIP2.Leaf
	assert.Nil(t, err)
	assert.True(t, tlsCertForIP == tlsCertForIP2)
	assert.Nil(t, x509c.VerifyHostname("192.168.0.1"))
}

func TestGenerateAndSave(t *testing.T) {
	caPath := "ca.crt"
	caKeyPath := "ca.key"

	err := GenerateAndSave(caPath, caKeyPath)

	assert.Nil(t, err)

	_ = os.Remove(caPath)
	_ = os.Remove(caKeyPath)
}
