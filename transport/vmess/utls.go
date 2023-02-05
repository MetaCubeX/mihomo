package vmess

import (
	"crypto/tls"
	"net"

	"github.com/Dreamacro/clash/log"

	"github.com/mroth/weightedrand/v2"
	utls "github.com/refraction-networking/utls"
)

type UConn struct {
	*utls.UConn
}

var initRandomFingerprint *utls.ClientHelloID

func UClient(c net.Conn, config *tls.Config, fingerprint *utls.ClientHelloID) net.Conn {
	utlsConn := utls.UClient(c, CopyConfig(config), *fingerprint)
	return &UConn{UConn: utlsConn}
}

func GetFingerprint(ClientFingerprint string) (*utls.ClientHelloID, bool) {
	if initRandomFingerprint == nil {
		initRandomFingerprint, _ = RollFingerprint()
	}
	if ClientFingerprint == "random" {
		log.Debugln("use initial random HelloID:%s", initRandomFingerprint.Client)
		return initRandomFingerprint, true
	}
	fingerprint, ok := Fingerprints[ClientFingerprint]
	log.Debugln("use specified fingerprint:%s", fingerprint.Client)
	return fingerprint, ok
}

func RollFingerprint() (*utls.ClientHelloID, bool) {
	chooser, _ := weightedrand.NewChooser(
		weightedrand.NewChoice("chrome", 6),
		weightedrand.NewChoice("safari", 3),
		weightedrand.NewChoice("ios", 2),
		weightedrand.NewChoice("firefox", 1),
	)
	initClient := chooser.Pick()
	log.Debugln("initial random HelloID:%s", initClient)
	fingerprint, ok := Fingerprints[initClient]
	return fingerprint, ok
}

var Fingerprints = map[string]*utls.ClientHelloID{
	"chrome":     &utls.HelloChrome_Auto,
	"firefox":    &utls.HelloFirefox_Auto,
	"safari":     &utls.HelloSafari_Auto,
	"ios":        &utls.HelloIOS_Auto,
	"randomized": &utls.HelloRandomized,
}

func CopyConfig(c *tls.Config) *utls.Config {
	return &utls.Config{
		RootCAs:               c.RootCAs,
		ServerName:            c.ServerName,
		InsecureSkipVerify:    c.InsecureSkipVerify,
		VerifyPeerCertificate: c.VerifyPeerCertificate,
	}
}

// WebsocketHandshake basically calls UConn.Handshake inside it but it will only send
// http/1.1 in its ALPN.
// Copy from https://github.com/XTLS/Xray-core/blob/main/transport/internet/tls/tls.go
func (c *UConn) WebsocketHandshake() error {
	// Build the handshake state. This will apply every variable of the TLS of the
	// fingerprint in the UConn
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	// Iterate over extensions and check for utls.ALPNExtension
	hasALPNExtension := false
	for _, extension := range c.Extensions {
		if alpn, ok := extension.(*utls.ALPNExtension); ok {
			hasALPNExtension = true
			alpn.AlpnProtocols = []string{"http/1.1"}
			break
		}
	}
	if !hasALPNExtension { // Append extension if doesn't exists
		c.Extensions = append(c.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
	}
	// Rebuild the client hello and do the handshake
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	return c.Handshake()
}
