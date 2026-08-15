package openvpn

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sort"
	"strings"
)

const (
	KeyMethod2 = 2

	keySourcePreMasterSize = 48
	keySourceRandomSize    = 32

	maxCipherKeyLength = 64
	maxHMACKeyLength   = 64
	keyBlockSize       = 2 * (maxCipherKeyLength + maxHMACKeyLength)

	keyExpansionID = "OpenVPN"
)

type KeySource struct {
	PreMaster [keySourcePreMasterSize]byte
	Random1   [keySourceRandomSize]byte
	Random2   [keySourceRandomSize]byte
}

type KeySource2 struct {
	Client KeySource
	Server KeySource
}

type KeyMaterial struct {
	SendCipherKey []byte
	SendHMACKey   []byte
	RecvCipherKey []byte
	RecvHMACKey   []byte
}

type KeyMethod2Record struct {
	Sources  KeySource2
	Options  string
	Username string
	Password string
	PeerInfo string
}

func NewClientKeyMethod2Record(options, peerInfo, username, password string) (*KeyMethod2Record, error) {
	var record KeyMethod2Record
	if _, err := rand.Read(record.Sources.Client.PreMaster[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(record.Sources.Client.Random1[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(record.Sources.Client.Random2[:]); err != nil {
		return nil, err
	}
	record.Options = options
	record.PeerInfo = peerInfo
	record.Username = username
	record.Password = password
	return &record, nil
}

func (r *KeyMethod2Record) MarshalClient() ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil key method 2 record")
	}
	out := make([]byte, 0, 4+1+keySourcePreMasterSize+keySourceRandomSize*2+len(r.Options)+16)
	out = binary.BigEndian.AppendUint32(out, 0)
	out = append(out, KeyMethod2)
	out = append(out, r.Sources.Client.PreMaster[:]...)
	out = append(out, r.Sources.Client.Random1[:]...)
	out = append(out, r.Sources.Client.Random2[:]...)
	out = appendOpenVPNString(out, r.Options)
	out = appendOpenVPNString(out, r.Username)
	out = appendOpenVPNString(out, r.Password)
	out = appendOpenVPNString(out, r.PeerInfo)
	return out, nil
}

var errKeyMethodPacketTooShort = errors.New("key method 2 packet too short")

func ParseServerKeyMethod2Record(packet []byte) (*KeyMethod2Record, error) {
	record, _, err := ParseServerKeyMethod2RecordConsumed(packet)
	return record, err
}

// ParseServerKeyMethod2RecordConsumed parses a server key-method-2 record and
// reports how many bytes were consumed so following TLS control data
// (PUSH_REPLY / AUTH_FAILED) can be preserved.
//
// OpenVPN 2.6 may omit the optional username, password and peer-info strings
// after the mandatory options string.
func ParseServerKeyMethod2RecordConsumed(packet []byte) (*KeyMethod2Record, int, error) {
	if len(packet) < 4+1+keySourceRandomSize*2 {
		return nil, 0, errKeyMethodPacketTooShort
	}
	if binary.BigEndian.Uint32(packet[:4]) != 0 {
		return nil, 0, errors.New("invalid key method 2 prefix")
	}
	if packet[4]&0x0f != KeyMethod2 {
		return nil, 0, fmt.Errorf("unsupported key method %d", packet[4])
	}
	offset := 5
	record := &KeyMethod2Record{}
	copy(record.Sources.Server.Random1[:], packet[offset:offset+keySourceRandomSize])
	offset += keySourceRandomSize
	copy(record.Sources.Server.Random2[:], packet[offset:offset+keySourceRandomSize])
	offset += keySourceRandomSize

	var err error
	record.Options, offset, err = readOpenVPNString(packet, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("read options: %w", err)
	}
	// Username / password / peer-info are written by OpenVPN 2.6 even when
	// empty. Only stop early when the remaining bytes are a following TLS
	// control message (PUSH_REPLY / AUTH_FAILED). A truncated length/value
	// is not a shortened record — the caller must keep reading.
	if record.Username, offset, err = readKM2TrailingString(packet, offset); err != nil {
		return nil, 0, err
	}
	if record.Password, offset, err = readKM2TrailingString(packet, offset); err != nil {
		return nil, 0, err
	}
	if record.PeerInfo, offset, err = readKM2TrailingString(packet, offset); err != nil {
		return nil, 0, err
	}
	return record, offset, nil
}

func readKM2TrailingString(packet []byte, offset int) (string, int, error) {
	s, next, err := readOpenVPNString(packet, offset)
	if err == nil {
		return s, next, nil
	}
	if errors.Is(err, ioStringEOF) && looksLikeFollowingTLSControl(packet[offset:]) {
		return "", offset, nil
	}
	return "", offset, err
}

// RecordComplete reports whether a full key-method-2 server record is present,
// and returns the consumed offset. It requires all four strings (OpenVPN 2.6
// writes them even when empty) so a standard record fragmented across TLS
// reads is not accepted prematurely.
func RecordComplete(packet []byte) (complete bool, consumed int) {
	if len(packet) < 4+1+keySourceRandomSize*2 {
		return false, 0
	}
	if binary.BigEndian.Uint32(packet[:4]) != 0 {
		return false, 0
	}
	if packet[4]&0x0f != KeyMethod2 {
		return false, 0
	}
	offset := 5 + keySourceRandomSize*2
	if !km2StrComplete(packet, offset) {
		return false, 0
	}
	offset += 2 + int(binary.BigEndian.Uint16(packet[offset:offset+2]))
	for i := 0; i < 3; i++ {
		if !km2StrComplete(packet, offset) {
			return false, 0
		}
		offset += 2 + int(binary.BigEndian.Uint16(packet[offset:offset+2]))
	}
	return true, offset
}

func km2StrComplete(packet []byte, offset int) bool {
	if offset+2 > len(packet) {
		return false
	}
	size := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
	if size == 0 {
		return true
	}
	return offset+2+size <= len(packet)
}

func looksLikeFollowingTLSControl(b []byte) bool {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	if len(b) == 0 {
		return false
	}
	return bytes.HasPrefix(b, []byte("PUSH_REPLY")) ||
		bytes.HasPrefix(b, []byte("AUTH_FAILED")) ||
		bytes.HasPrefix(b, []byte("PUSH_REQUEST")) ||
		bytes.HasPrefix(b, []byte("AUTH_PENDING")) ||
		bytes.HasPrefix(b, []byte("INFO_PRE")) ||
		bytes.HasPrefix(b, []byte("INFO")) ||
		bytes.HasPrefix(b, []byte("RESTART")) ||
		bytes.HasPrefix(b, []byte("HALT")) ||
		bytes.HasPrefix(b, []byte("EXIT")) ||
		bytes.HasPrefix(b, []byte("CR_RESPONSE"))
}

func DeriveClientKeyMaterial(sources KeySource2, clientSession, serverSession SessionID, cipherKeyLen int) (*KeyMaterial, error) {
	if cipherKeyLen != 16 && cipherKeyLen != 24 && cipherKeyLen != 32 {
		return nil, fmt.Errorf("unsupported data cipher key length %d", cipherKeyLen)
	}
	var master [48]byte
	if err := openvpnPRF(
		sources.Client.PreMaster[:],
		keyExpansionID+" master secret",
		sources.Client.Random1[:],
		sources.Server.Random1[:],
		nil,
		nil,
		master[:],
	); err != nil {
		return nil, err
	}

	keyBlock := make([]byte, keyBlockSize)
	if err := openvpnPRF(
		master[:],
		keyExpansionID+" key expansion",
		sources.Client.Random2[:],
		sources.Server.Random2[:],
		clientSession[:],
		serverSession[:],
		keyBlock,
	); err != nil {
		return nil, err
	}

	clientToServer := keyBlock[:maxCipherKeyLength+maxHMACKeyLength]
	serverToClient := keyBlock[maxCipherKeyLength+maxHMACKeyLength:]
	return &KeyMaterial{
		SendCipherKey: cloneBytes(clientToServer[:cipherKeyLen]),
		SendHMACKey:   cloneBytes(clientToServer[maxCipherKeyLength : maxCipherKeyLength+maxHMACKeyLength]),
		RecvCipherKey: cloneBytes(serverToClient[:cipherKeyLen]),
		RecvHMACKey:   cloneBytes(serverToClient[maxCipherKeyLength : maxCipherKeyLength+maxHMACKeyLength]),
	}, nil
}

func InstallScriptOptionsString(proto, cipher, auth string, compLZO string) string {
	protoName := "UDPv4"
	if proto == ProtoTCP {
		protoName = "TCPv4_CLIENT"
	}
	keysize := "128"
	if cipher == CipherAES256GCM || cipher == CipherAES256CBC || cipher == CipherChaCha20Poly1305 {
		keysize = "256"
	}
	mtu := "1550"
	comp := ""
	if compLZO == CompLzoYes {
		mtu = "1544"
		comp = "comp-lzo,"
	}
	return fmt.Sprintf("V4,dev-type tun,link-mtu %s,tun-mtu 1500,proto %s,%scipher %s,auth %s,keysize %s,key-method 2,tls-client", mtu, protoName, comp, cipher, auth, keysize)
}

func InstallScriptPeerInfo(cipher string, dataCiphers []string, compLZO string, peerInfo map[string]string) string {
	ivVer := "mihomo-openvpn"
	if value, ok := peerInfo["IV_VER"]; ok {
		ivVer = value
	}
	lzo := ""
	if compLZO == CompLzoYes {
		lzo = "IV_LZO=1\n"
	}
	// Build the IV_CIPHERS string. If a data-ciphers list is configured,
	// send all entries colon-separated. Otherwise, send just the single cipher.
	ivCiphers := cipher
	if len(dataCiphers) > 0 {
		normalized := make([]string, len(dataCiphers))
		for i, c := range dataCiphers {
			normalized[i] = normalizeCipher(c)
		}
		ivCiphers = strings.Join(normalized, ":")
	}
	// IV_PROTO advertises DATA_V2 (bit 1), REQUEST_PUSH (bit 2) and
	// AUTH_PENDING keyword support (bit 4). The parser supports
	// AUTH_PENDING,timeout N, so capability and behavior must agree.
	const ivProto = (1 << 1) | (1 << 2) | (1 << 4) // 22
	info := fmt.Sprintf("IV_VER=%s\nIV_PROTO=%d\n%sIV_CIPHERS=%s\n", ivVer, ivProto, lzo, ivCiphers)
	// Append user-defined peer-info entries (e.g. IV_HWADDR, UV_*) after the
	// built-in fields. Keys are sorted so the output is deterministic.
	keys := make([]string, 0, len(peerInfo))
	for key := range peerInfo {
		switch key {
		case "IV_VER", "IV_PROTO", "IV_CIPHERS":
			continue
		case "IV_LZO":
			if lzo != "" {
				continue
			}
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		info += fmt.Sprintf("%s=%s\n", key, peerInfo[key])
	}
	return info
}

func appendOpenVPNString(out []byte, s string) []byte {
	if s == "" {
		return binary.BigEndian.AppendUint16(out, 0)
	}
	if len(s)+1 > 0xffff {
		s = s[:0xfffe]
	}
	out = binary.BigEndian.AppendUint16(out, uint16(len(s)+1))
	out = append(out, s...)
	out = append(out, 0)
	return out
}

func readOpenVPNString(packet []byte, offset int) (string, int, error) {
	if offset+2 > len(packet) {
		return "", offset, ioStringEOF
	}
	size := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
	if size == 0 {
		return "", offset + 2, nil
	}
	if offset+2+size > len(packet) {
		// Do not consume the length prefix: leftover bytes may be PUSH_REPLY.
		return "", offset, ioStringEOF
	}
	raw := packet[offset+2 : offset+2+size]
	if raw[len(raw)-1] == 0 {
		raw = raw[:len(raw)-1]
	}
	return string(raw), offset + 2 + size, nil
}

var ioStringEOF = errors.New("openvpn string truncated")

func openvpnPRF(secret []byte, label string, clientSeed, serverSeed, clientSession, serverSession []byte, out []byte) error {
	seed := make([]byte, 0, len(label)+len(clientSeed)+len(serverSeed)+len(clientSession)+len(serverSession))
	seed = append(seed, label...)
	seed = append(seed, clientSeed...)
	seed = append(seed, serverSeed...)
	seed = append(seed, clientSession...)
	seed = append(seed, serverSession...)

	split := (len(secret) + 1) / 2
	s1 := secret[:split]
	s2 := secret[len(secret)-split:]

	md5Out := pHash(md5.New, s1, seed, len(out))
	sha1Out := pHash(sha1.New, s2, seed, len(out))
	for i := range out {
		out[i] = md5Out[i] ^ sha1Out[i]
	}
	return nil
}

func pHash(newHash func() hash.Hash, secret, seed []byte, size int) []byte {
	out := make([]byte, 0, size)
	a := hmacSum(newHash, secret, seed)
	for len(out) < size {
		chunkInput := make([]byte, 0, len(a)+len(seed))
		chunkInput = append(chunkInput, a...)
		chunkInput = append(chunkInput, seed...)
		out = append(out, hmacSum(newHash, secret, chunkInput)...)
		a = hmacSum(newHash, secret, a)
	}
	return out[:size]
}

func hmacSum(newHash func() hash.Hash, key, data []byte) []byte {
	mac := hmac.New(newHash, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}
