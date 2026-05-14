package openvpn

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
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

func ParseServerKeyMethod2Record(packet []byte) (*KeyMethod2Record, error) {
	if len(packet) < 4+1+keySourceRandomSize*2 {
		return nil, errors.New("key method 2 packet too short")
	}
	if binary.BigEndian.Uint32(packet[:4]) != 0 {
		return nil, errors.New("invalid key method 2 prefix")
	}
	if packet[4]&0x0f != KeyMethod2 {
		return nil, fmt.Errorf("unsupported key method %d", packet[4])
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
		return nil, fmt.Errorf("read options: %w", err)
	}
	record.Username, offset, _ = readOpenVPNString(packet, offset)
	record.Password, offset, _ = readOpenVPNString(packet, offset)
	record.PeerInfo, _, _ = readOpenVPNString(packet, offset)
	return record, nil
}

func DeriveClientKeyMaterial(sources KeySource2, clientSession, serverSession SessionID, cipherKeyLen int) (*KeyMaterial, error) {
	if cipherKeyLen != 16 && cipherKeyLen != 32 {
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

func InstallScriptOptionsString(proto, cipher, auth string) string {
	protoName := "UDPv4"
	if proto == ProtoTCP {
		protoName = "TCPv4_CLIENT"
	}
	keysize := "128"
	if cipher == CipherAES256GCM {
		keysize = "256"
	}
	return fmt.Sprintf("V4,dev-type tun,link-mtu 1550,tun-mtu 1500,proto %s,cipher %s,auth %s,keysize %s,key-method 2,tls-client", protoName, cipher, auth, keysize)
}

func InstallScriptPeerInfo(cipher string) string {
	return fmt.Sprintf("IV_VER=mihomo-openvpn\nIV_PROTO=6\nIV_CIPHERS=%s\n", cipher)
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
	offset += 2
	if size == 0 {
		return "", offset, nil
	}
	if offset+size > len(packet) {
		return "", offset, ioStringEOF
	}
	raw := packet[offset : offset+size]
	offset += size
	if raw[len(raw)-1] == 0 {
		raw = raw[:len(raw)-1]
	}
	return string(raw), offset, nil
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
