package openvpn

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

const (
	AESGCMTagSize = 16
	AESGCMIVSize  = 12

	PeerIDUnset uint32 = 0xffffff
)

type DataChannel struct {
	send cipher.AEAD
	recv cipher.AEAD

	sendImplicitIV [AESGCMIVSize]byte
	recvImplicitIV [AESGCMIVSize]byte

	keyID  uint8
	peerID uint32

	mu           sync.Mutex
	sendPacketID uint32
	recvHighest  uint32
	recvSeen     bool
}

func NewDataChannel(keys *KeyMaterial, peerID uint32) (*DataChannel, error) {
	if keys == nil {
		return nil, errors.New("nil openvpn key material")
	}
	sendBlock, err := aes.NewCipher(keys.SendCipherKey)
	if err != nil {
		return nil, fmt.Errorf("create send cipher: %w", err)
	}
	recvBlock, err := aes.NewCipher(keys.RecvCipherKey)
	if err != nil {
		return nil, fmt.Errorf("create recv cipher: %w", err)
	}
	send, err := cipher.NewGCMWithTagSize(sendBlock, AESGCMTagSize)
	if err != nil {
		return nil, fmt.Errorf("create send gcm: %w", err)
	}
	recv, err := cipher.NewGCMWithTagSize(recvBlock, AESGCMTagSize)
	if err != nil {
		return nil, fmt.Errorf("create recv gcm: %w", err)
	}
	if len(keys.SendHMACKey) < AESGCMIVSize-4 || len(keys.RecvHMACKey) < AESGCMIVSize-4 {
		return nil, errors.New("openvpn implicit IV keys are too short")
	}
	d := &DataChannel{
		send:   send,
		recv:   recv,
		peerID: peerID,
	}
	copy(d.sendImplicitIV[4:], keys.SendHMACKey[:AESGCMIVSize-4])
	copy(d.recvImplicitIV[4:], keys.RecvHMACKey[:AESGCMIVSize-4])
	return d, nil
}

func (d *DataChannel) Encrypt(packet []byte) ([]byte, error) {
	if d == nil {
		return nil, errors.New("nil openvpn data channel")
	}

	d.mu.Lock()
	d.sendPacketID++
	packetID := d.sendPacketID
	d.mu.Unlock()

	header := d.dataHeader()
	var packetIDBytes [4]byte
	binary.BigEndian.PutUint32(packetIDBytes[:], packetID)
	nonce := d.nonce(packetID, d.sendImplicitIV)
	ad := make([]byte, 0, len(header)+len(packetIDBytes))
	ad = append(ad, header...)
	ad = append(ad, packetIDBytes[:]...)
	sealed := d.send.Seal(nil, nonce[:], packet, ad)

	out := make([]byte, 0, len(header)+4+AESGCMTagSize+len(packet))
	out = append(out, header...)
	out = append(out, packetIDBytes[:]...)
	out = append(out, sealed[len(sealed)-AESGCMTagSize:]...)
	out = append(out, sealed[:len(sealed)-AESGCMTagSize]...)
	return out, nil
}

func (d *DataChannel) Decrypt(packet []byte) ([]byte, error) {
	if d == nil {
		return nil, errors.New("nil openvpn data channel")
	}
	if len(packet) < 1 {
		return nil, errors.New("empty openvpn data packet")
	}
	opcode, _ := parseOpcodeKeyID(packet[0])
	headerSize := 1
	if opcode == PDataV2 {
		headerSize = 4
	}
	if opcode != PDataV1 && opcode != PDataV2 {
		return nil, fmt.Errorf("not an openvpn data packet: %s", opcode)
	}
	if len(packet) < headerSize+4+AESGCMTagSize+1 {
		return nil, errors.New("openvpn data packet too short")
	}
	header := packet[:headerSize]
	packetIDBytes := packet[headerSize : headerSize+4]
	packetID := binary.BigEndian.Uint32(packetIDBytes)
	tag := packet[headerSize+4 : headerSize+4+AESGCMTagSize]
	ciphertext := packet[headerSize+4+AESGCMTagSize:]
	combined := make([]byte, 0, len(ciphertext)+AESGCMTagSize)
	combined = append(combined, ciphertext...)
	combined = append(combined, tag...)
	ad := make([]byte, 0, len(header)+len(packetIDBytes))
	ad = append(ad, header...)
	ad = append(ad, packetIDBytes...)

	nonce := d.nonce(packetID, d.recvImplicitIV)
	plain, err := d.recv.Open(nil, nonce[:], combined, ad)
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	if d.recvSeen && packetID <= d.recvHighest {
		d.mu.Unlock()
		return nil, fmt.Errorf("openvpn replayed data packet id %d", packetID)
	}
	d.recvHighest = packetID
	d.recvSeen = true
	d.mu.Unlock()
	return plain, nil
}

func (d *DataChannel) dataHeader() []byte {
	if d.peerID != PeerIDUnset {
		return []byte{
			opcodeKeyID(PDataV2, d.keyID),
			byte(d.peerID >> 16),
			byte(d.peerID >> 8),
			byte(d.peerID),
		}
	}
	return []byte{opcodeKeyID(PDataV1, d.keyID)}
}

func (d *DataChannel) nonce(packetID uint32, implicit [AESGCMIVSize]byte) [AESGCMIVSize]byte {
	nonce := implicit
	binary.BigEndian.PutUint32(nonce[:4], binary.BigEndian.Uint32(nonce[:4])^packetID)
	return nonce
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
