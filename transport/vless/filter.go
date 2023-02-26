package vless

import (
	"bytes"
	"encoding/binary"

	log "github.com/sirupsen/logrus"
)

var (
	tls13SupportedVersions  = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	tlsClientHandshakeStart = []byte{0x16, 0x03}
	tlsServerHandshakeStart = []byte{0x16, 0x03, 0x03}
	tlsApplicationDataStart = []byte{0x17, 0x03, 0x03}

	tls13CipherSuiteMap = map[uint16]string{
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		0x1304: "TLS_AES_128_CCM_SHA256",
		0x1305: "TLS_AES_128_CCM_8_SHA256",
	}
)

const (
	tlsHandshakeTypeClientHello byte = 0x01
	tlsHandshakeTypeServerHello byte = 0x02
)

func (vc *Conn) FilterTLS(p []byte) (index int) {
	if vc.packetsToFilter <= 0 {
		return 0
	}
	lenP := len(p)
	vc.packetsToFilter -= 1
	if index = bytes.Index(p, tlsServerHandshakeStart); index != -1 {
		if lenP >= index+5 && p[index+5] == tlsHandshakeTypeServerHello {
			vc.remainingServerHello = binary.BigEndian.Uint16(p[index+3:]) + 5
			vc.isTLS = true
			vc.isTLS12orAbove = true
			if lenP-index >= 79 && vc.remainingServerHello >= 79 {
				sessionIDLen := int(p[index+43])
				vc.cipher = binary.BigEndian.Uint16(p[index+43+sessionIDLen+1:])
			}
		}
	} else if index = bytes.Index(p, tlsClientHandshakeStart); index != -1 {
		if lenP >= index+5 && p[index+5] == tlsHandshakeTypeClientHello {
			vc.isTLS = true
		}
	}

	if vc.remainingServerHello > 0 {
		end := int(vc.remainingServerHello)
		i := index
		if i < 0 {
			i = 0
		}
		if i+end > lenP {
			end = lenP
			vc.remainingServerHello -= uint16(end - i)
		} else {
			vc.remainingServerHello -= uint16(end)
			end += i
		}
		if bytes.Contains(p[i:end], tls13SupportedVersions) {
			// TLS 1.3 Client Hello
			cs, ok := tls13CipherSuiteMap[vc.cipher]
			if ok && cs != "TLS_AES_128_CCM_8_SHA256" {
				vc.enableXTLS = true
			}
			log.Debugln("XTLS Vision found TLS 1.3, packetLength=", lenP, ", CipherSuite=", cs)
			vc.packetsToFilter = 0
			return
		} else if vc.remainingServerHello <= 0 {
			log.Debugln("XTLS Vision found TLS 1.2, packetLength=", lenP)
			vc.packetsToFilter = 0
			return
		}
		log.Debugln("XTLS Vision found inconclusive server hello, packetLength=", lenP,
			", remainingServerHelloBytes=", vc.remainingServerHello)
	}
	if vc.packetsToFilter <= 0 {
		log.Debugln("XTLS Vision stop filtering")
	}
	return
}
