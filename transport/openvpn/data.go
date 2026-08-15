package openvpn

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	DataChannelTagSize      = 16
	DataChannelIVSize       = 12
	DataChannelCBCIVSize    = aes.BlockSize
	dataChannelIVRandBuf    = 32 * 1024
	dataChannelReplayWindow = 64

	PeerIDUnset uint32 = 0xffffff
)

// OpenVPN data-channel ping payload, matching PING_STRING in upstream OpenVPN.
var openVPNPingPacket = []byte{
	0x2a, 0x18, 0x7b, 0xf3,
	0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a,
	0x98, 0x1f, 0xc7, 0x48,
}

func IsPingPacket(packet []byte) bool {
	return bytes.Equal(packet, openVPNPingPacket)
}

type DataChannel struct {
	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD

	sendBlock   cipher.Block
	recvBlock   cipher.Block
	sendHMACKey []byte
	recvHMACKey []byte
	authHash    func() hash.Hash
	authSize    int
	sendMACPool sync.Pool
	recvMACPool sync.Pool

	sendImplicitIV [DataChannelIVSize]byte
	recvImplicitIV [DataChannelIVSize]byte

	keyID  uint8
	peerID uint32
	header []byte

	mu           sync.Mutex
	sendPacketID uint32
	// recvEvidence latches true once a data packet labeled with this key ID
	// decrypted successfully. The peer only labels outbound packets with a
	// key whose authentication completed (OpenVPN tls_pre_encrypt /
	// handle_data_channel_packet require KS_AUTH_TRUE), so this is the
	// reliable signal that this epoch has been activated by the peer and can
	// replace the lame-duck for outbound traffic. Stored per-epoch so a
	// back-to-back rekey cannot attribute an older epoch's evidence to a
	// newer key. Guarded by d.mu.
	recvEvidence bool
	recvHighest  uint32
	recvWindow   uint64
	recvSeen     bool

	randMu     sync.Mutex
	randBuf    []byte
	randOffset int
}

func NewDataChannel(keys *KeyMaterial, cipherName, authName string, peerID uint32, keyID uint8) (*DataChannel, error) {
	if keys == nil {
		return nil, errors.New("nil openvpn key material")
	}
	if isDataChannelAEAD(cipherName) {
		send, err := newDataChannelAEAD(cipherName, keys.SendCipherKey)
		if err != nil {
			return nil, fmt.Errorf("create send cipher: %w", err)
		}
		recv, err := newDataChannelAEAD(cipherName, keys.RecvCipherKey)
		if err != nil {
			return nil, fmt.Errorf("create recv cipher: %w", err)
		}
		if len(keys.SendHMACKey) < DataChannelIVSize-4 || len(keys.RecvHMACKey) < DataChannelIVSize-4 {
			return nil, errors.New("openvpn implicit IV keys are too short")
		}
		d := &DataChannel{
			sendAEAD: send,
			recvAEAD: recv,
			keyID:    keyID & KeyIDMask,
			peerID:   peerID,
			header:   dataHeader(peerID, keyID),
		}
		copy(d.sendImplicitIV[4:], keys.SendHMACKey[:DataChannelIVSize-4])
		copy(d.recvImplicitIV[4:], keys.RecvHMACKey[:DataChannelIVSize-4])
		return d, nil
	}

	send, err := newDataChannelCBC(cipherName, keys.SendCipherKey)
	if err != nil {
		return nil, fmt.Errorf("create send cipher: %w", err)
	}
	recv, err := newDataChannelCBC(cipherName, keys.RecvCipherKey)
	if err != nil {
		return nil, fmt.Errorf("create recv cipher: %w", err)
	}
	authHash, authSize, err := newDataChannelAuth(authName)
	if err != nil {
		return nil, err
	}
	if len(keys.SendHMACKey) < authSize || len(keys.RecvHMACKey) < authSize {
		return nil, errors.New("openvpn HMAC keys are too short")
	}
	d := &DataChannel{
		sendBlock:   send,
		recvBlock:   recv,
		sendHMACKey: append([]byte(nil), keys.SendHMACKey[:authSize]...),
		recvHMACKey: append([]byte(nil), keys.RecvHMACKey[:authSize]...),
		authHash:    authHash,
		authSize:    authSize,
		keyID:       keyID & KeyIDMask,
		peerID:      peerID,
		header:      dataHeader(peerID, keyID),
	}
	d.sendMACPool.New = func() any {
		return hmac.New(d.authHash, d.sendHMACKey)
	}
	d.recvMACPool.New = func() any {
		return hmac.New(d.authHash, d.recvHMACKey)
	}
	return d, nil
}

func isDataChannelAEAD(cipherName string) bool {
	switch cipherName {
	case CipherAES128GCM, CipherAES192GCM, CipherAES256GCM, CipherChaCha20Poly1305:
		return true
	default:
		return false
	}
}

func newDataChannelAEAD(cipherName string, key []byte) (cipher.AEAD, error) {
	switch cipherName {
	case CipherAES128GCM, CipherAES192GCM, CipherAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCMWithTagSize(block, DataChannelTagSize)
	case CipherChaCha20Poly1305:
		return chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("unsupported openvpn cipher %q", cipherName)
	}
}

func newDataChannelCBC(cipherName string, key []byte) (cipher.Block, error) {
	switch cipherName {
	case CipherAESCBC, CipherAES128CBC, CipherAES192CBC, CipherAES256CBC:
		return aes.NewCipher(key)
	default:
		return nil, fmt.Errorf("unsupported openvpn cipher %q", cipherName)
	}
}

func newDataChannelAuth(authName string) (func() hash.Hash, int, error) {
	switch authName {
	case AuthMD5:
		return md5.New, md5.Size, nil
	case AuthSHA1:
		return sha1.New, sha1.Size, nil
	case AuthSHA256:
		return sha256.New, sha256.Size, nil
	case AuthSHA384:
		return sha512.New384, sha512.Size384, nil
	case AuthSHA512:
		return sha512.New, sha512.Size, nil
	default:
		return nil, 0, fmt.Errorf("unsupported openvpn auth %q", authName)
	}
}

func (d *DataChannel) Encrypt(packet []byte) ([]byte, error) {
	if d == nil {
		return nil, errors.New("nil openvpn data channel")
	}

	packetID, err := d.nextPacketID()
	if err != nil {
		return nil, err
	}
	var encrypted []byte
	if d.sendAEAD != nil {
		encrypted, err = d.encryptAEAD(packet, packetID)
	} else {
		encrypted, err = d.encryptCBC(packet, packetID)
	}
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func (d *DataChannel) encryptAEAD(packet []byte, packetID uint32) ([]byte, error) {
	header := d.header
	var packetIDBytes [4]byte
	binary.BigEndian.PutUint32(packetIDBytes[:], packetID)
	nonce := d.nonce(packetID, d.sendImplicitIV)
	ad := make([]byte, 0, len(header)+len(packetIDBytes))
	ad = append(ad, header...)
	ad = append(ad, packetIDBytes[:]...)
	sealed := d.sendAEAD.Seal(nil, nonce[:], packet, ad)

	out := make([]byte, 0, len(header)+4+DataChannelTagSize+len(packet))
	out = append(out, header...)
	out = append(out, packetIDBytes[:]...)
	out = append(out, sealed[len(sealed)-DataChannelTagSize:]...)
	out = append(out, sealed[:len(sealed)-DataChannelTagSize]...)
	return out, nil
}

func (d *DataChannel) encryptCBC(packet []byte, packetID uint32) ([]byte, error) {
	header := d.header
	blockSize := d.sendBlock.BlockSize()
	plainLen := 4 + len(packet)
	padding := blockSize - plainLen%blockSize
	if padding == 0 {
		padding = blockSize
	}
	out := make([]byte, len(header)+d.authSize+DataChannelCBCIVSize+plainLen+padding)
	copy(out, header)
	authenticated := out[len(header)+d.authSize:]
	iv := authenticated[:DataChannelCBCIVSize]
	if err := d.fillCBCIV(iv); err != nil {
		return nil, err
	}
	ciphertext := authenticated[DataChannelCBCIVSize:]
	binary.BigEndian.PutUint32(ciphertext[:4], packetID)
	copy(ciphertext[4:], packet)
	for i := plainLen; i < len(ciphertext); i++ {
		ciphertext[i] = byte(padding)
	}
	cipher.NewCBCEncrypter(d.sendBlock, iv).CryptBlocks(ciphertext, ciphertext)
	d.hmacCopy(&d.sendMACPool, authenticated, out[len(header):])
	return out, nil
}

func (d *DataChannel) Decrypt(packet []byte) ([]byte, error) {
	if d == nil {
		return nil, errors.New("nil openvpn data channel")
	}
	headerSize, err := dataPacketHeaderSize(packet)
	if err != nil {
		return nil, err
	}
	if d.recvAEAD != nil {
		return d.decryptAEAD(packet, headerSize)
	}
	return d.decryptCBC(packet, headerSize)
}

func (d *DataChannel) decryptAEAD(packet []byte, headerSize int) ([]byte, error) {
	if len(packet) < 1 {
		return nil, errors.New("empty openvpn data packet")
	}
	if len(packet) < headerSize+4+DataChannelTagSize+1 {
		return nil, errors.New("openvpn data packet too short")
	}
	header := packet[:headerSize]
	packetIDBytes := packet[headerSize : headerSize+4]
	packetID := binary.BigEndian.Uint32(packetIDBytes)
	tag := packet[headerSize+4 : headerSize+4+DataChannelTagSize]
	ciphertext := packet[headerSize+4+DataChannelTagSize:]
	combined := make([]byte, 0, len(ciphertext)+DataChannelTagSize)
	combined = append(combined, ciphertext...)
	combined = append(combined, tag...)
	ad := make([]byte, 0, len(header)+len(packetIDBytes))
	ad = append(ad, header...)
	ad = append(ad, packetIDBytes...)

	nonce := d.nonce(packetID, d.recvImplicitIV)
	plain, err := d.recvAEAD.Open(nil, nonce[:], combined, ad)
	if err != nil {
		return nil, err
	}

	if err := d.acceptPacketID(packetID); err != nil {
		return nil, err
	}
	return plain, nil
}

func (d *DataChannel) decryptCBC(packet []byte, headerSize int) ([]byte, error) {
	blockSize := d.recvBlock.BlockSize()
	minPacketLen := headerSize + d.authSize + blockSize + blockSize
	if len(packet) < minPacketLen {
		return nil, errors.New("openvpn CBC data packet too short")
	}

	body := packet[headerSize:]
	tag := body[:d.authSize]
	authenticated := body[d.authSize:]
	var expectedBuf [sha256.Size]byte
	expected := d.hmacAppend(&d.recvMACPool, authenticated, expectedBuf[:0])
	if !hmac.Equal(tag, expected) {
		return nil, errors.New("openvpn CBC data packet HMAC authentication failed")
	}

	iv := authenticated[:blockSize]
	ciphertext := authenticated[blockSize:]
	if len(ciphertext) == 0 || len(ciphertext)%blockSize != 0 {
		return nil, errors.New("invalid openvpn CBC ciphertext length")
	}
	cipher.NewCBCDecrypter(d.recvBlock, iv).CryptBlocks(ciphertext, ciphertext)
	plain, err := pkcs7Unpad(ciphertext, blockSize)
	if err != nil {
		return nil, err
	}
	if len(plain) < 4 {
		return nil, errors.New("openvpn CBC plaintext missing packet id")
	}

	packetID := binary.BigEndian.Uint32(plain[:4])
	if err := d.acceptPacketID(packetID); err != nil {
		return nil, err
	}
	return plain[4:], nil
}

func dataPacketHeaderSize(packet []byte) (int, error) {
	if len(packet) < 1 {
		return 0, errors.New("empty openvpn data packet")
	}
	opcode, _ := parseOpcodeKeyID(packet[0])
	switch opcode {
	case PDataV1:
		return 1, nil
	case PDataV2:
		if len(packet) < 4 {
			return 0, errors.New("openvpn P_DATA_V2 packet missing peer id")
		}
		return 4, nil
	default:
		return 0, fmt.Errorf("not an openvpn data packet: %s", opcode)
	}
}

const dataPacketIDRekeyThreshold = uint32(0xFF000000)

var errDataPacketIDExhausted = errors.New("openvpn data packet id reached rekey threshold")

func (d *DataChannel) nextPacketID() (uint32, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	// OpenVPN starts a soft reset once packet_id_close_to_wrapping reaches
	// this threshold. This client cannot initiate that reset yet, so surface
	// the condition and let the adapter reconnect instead of silently
	// blackholing packets or approaching nonce reuse.
	if d.sendPacketID >= dataPacketIDRekeyThreshold {
		return 0, errDataPacketIDExhausted
	}
	d.sendPacketID++
	return d.sendPacketID, nil
}

// MarkPeerActive records that a packet labeled with this key ID decrypted
// successfully, i.e. the peer has activated this epoch.
func (d *DataChannel) MarkPeerActive() {
	d.mu.Lock()
	d.recvEvidence = true
	d.mu.Unlock()
}

// PeerActive reports whether the peer has activated this epoch.
func (d *DataChannel) PeerActive() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.recvEvidence
}

func (d *DataChannel) acceptPacketID(packetID uint32) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.recvSeen {
		d.recvHighest = packetID
		d.recvWindow = 1
		d.recvSeen = true
		return nil
	}

	if packetID > d.recvHighest {
		shift := packetID - d.recvHighest
		if shift >= dataChannelReplayWindow {
			d.recvWindow = 1
		} else {
			d.recvWindow = d.recvWindow<<shift | 1
		}
		d.recvHighest = packetID
		return nil
	}

	diff := d.recvHighest - packetID
	if diff >= dataChannelReplayWindow {
		return fmt.Errorf("openvpn replayed data packet id %d", packetID)
	}
	mask := uint64(1) << diff
	if d.recvWindow&mask != 0 {
		return fmt.Errorf("openvpn replayed data packet id %d", packetID)
	}
	d.recvWindow |= mask
	return nil
}

func dataHeader(peerID uint32, keyID uint8) []byte {
	if peerID != PeerIDUnset {
		return []byte{
			opcodeKeyID(PDataV2, keyID),
			byte(peerID >> 16),
			byte(peerID >> 8),
			byte(peerID),
		}
	}
	return []byte{opcodeKeyID(PDataV1, keyID)}
}

func (d *DataChannel) nonce(packetID uint32, implicit [DataChannelIVSize]byte) [DataChannelIVSize]byte {
	nonce := implicit
	binary.BigEndian.PutUint32(nonce[:4], binary.BigEndian.Uint32(nonce[:4])^packetID)
	return nonce
}

func (d *DataChannel) fillCBCIV(iv []byte) error {
	d.randMu.Lock()
	defer d.randMu.Unlock()

	for len(iv) > 0 {
		if d.randOffset == len(d.randBuf) {
			if d.randBuf == nil {
				d.randBuf = make([]byte, dataChannelIVRandBuf)
			}
			if _, err := rand.Read(d.randBuf); err != nil {
				return err
			}
			d.randOffset = 0
		}
		n := copy(iv, d.randBuf[d.randOffset:])
		d.randOffset += n
		iv = iv[n:]
	}
	return nil
}

func (d *DataChannel) hmacAppend(pool *sync.Pool, data, dst []byte) []byte {
	mac := pool.Get().(hash.Hash)
	defer pool.Put(mac)
	mac.Reset()
	_, _ = mac.Write(data)
	return mac.Sum(dst)
}

// hmacCopy writes the HMAC of data into dst (which must have enough
// capacity), returning the number of bytes written. Unlike hmacAppend it
// does not rely on mac.Sum(dst) appending into dst's backing array — it
// always writes the tag into dst explicitly.
func (d *DataChannel) hmacCopy(pool *sync.Pool, data, dst []byte) int {
	mac := pool.Get().(hash.Hash)
	defer pool.Put(mac)
	mac.Reset()
	_, _ = mac.Write(data)
	n := copy(dst, mac.Sum(nil))
	return n
}

func pkcs7Unpad(padded []byte, blockSize int) ([]byte, error) {
	if len(padded) == 0 || len(padded)%blockSize != 0 {
		return nil, errors.New("invalid openvpn CBC padding length")
	}
	padding := int(padded[len(padded)-1])
	if padding == 0 || padding > blockSize || padding > len(padded) {
		return nil, errors.New("invalid openvpn CBC padding")
	}
	for _, b := range padded[len(padded)-padding:] {
		if int(b) != padding {
			return nil, errors.New("invalid openvpn CBC padding")
		}
	}
	return padded[:len(padded)-padding], nil
}

func ParsePeerID(options string) uint32 {
	for _, field := range splitPushOptions(options) {
		if len(field) > len("peer-id ") && field[:len("peer-id ")] == "peer-id " {
			var id uint32
			if _, err := fmt.Sscanf(field, "peer-id %d", &id); err == nil && id <= PeerIDUnset {
				return id
			}
		}
	}
	return PeerIDUnset
}
