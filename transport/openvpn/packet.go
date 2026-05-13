package openvpn

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	KeyIDMask   = 0x07
	OpcodeShift = 3

	PControlHardResetClientV1 Opcode = 1
	PControlHardResetServerV1 Opcode = 2
	PControlSoftResetV1       Opcode = 3
	PControlV1                Opcode = 4
	PAckV1                    Opcode = 5
	PDataV1                   Opcode = 6
	PControlHardResetClientV2 Opcode = 7
	PControlHardResetServerV2 Opcode = 8
	PDataV2                   Opcode = 9
	PControlHardResetClientV3 Opcode = 10
	PControlWKCV1             Opcode = 11

	SessionIDSize = 8
)

type Opcode uint8

func (o Opcode) String() string {
	switch o {
	case PControlHardResetClientV1:
		return "P_CONTROL_HARD_RESET_CLIENT_V1"
	case PControlHardResetServerV1:
		return "P_CONTROL_HARD_RESET_SERVER_V1"
	case PControlSoftResetV1:
		return "P_CONTROL_SOFT_RESET_V1"
	case PControlV1:
		return "P_CONTROL_V1"
	case PAckV1:
		return "P_ACK_V1"
	case PDataV1:
		return "P_DATA_V1"
	case PControlHardResetClientV2:
		return "P_CONTROL_HARD_RESET_CLIENT_V2"
	case PControlHardResetServerV2:
		return "P_CONTROL_HARD_RESET_SERVER_V2"
	case PDataV2:
		return "P_DATA_V2"
	case PControlHardResetClientV3:
		return "P_CONTROL_HARD_RESET_CLIENT_V3"
	case PControlWKCV1:
		return "P_CONTROL_WKC_V1"
	default:
		return "P_UNKNOWN"
	}
}

func (o Opcode) IsControl() bool {
	switch o {
	case PControlHardResetClientV1, PControlHardResetServerV1, PControlSoftResetV1, PControlV1,
		PAckV1, PControlHardResetClientV2, PControlHardResetServerV2, PControlHardResetClientV3, PControlWKCV1:
		return true
	default:
		return false
	}
}

func (o Opcode) HasMessageID() bool {
	return o.IsControl() && o != PAckV1
}

type SessionID [SessionIDSize]byte

func NewSessionID() (SessionID, error) {
	var id SessionID
	_, err := rand.Read(id[:])
	return id, err
}

type ControlPacket struct {
	Opcode       Opcode
	KeyID        uint8
	LocalSession SessionID

	AckIDs           []uint32
	AckRemoteSession SessionID

	MessageID uint32
	Payload   []byte
}

func opcodeKeyID(opcode Opcode, keyID uint8) byte {
	return byte(opcode)<<OpcodeShift | (keyID & KeyIDMask)
}

func parseOpcodeKeyID(b byte) (Opcode, uint8) {
	return Opcode(b >> OpcodeShift), b & KeyIDMask
}

func (p ControlPacket) EncodePlain() ([]byte, error) {
	if !p.Opcode.IsControl() {
		return nil, fmt.Errorf("opcode %s is not a control opcode", p.Opcode)
	}
	if len(p.AckIDs) > 255 {
		return nil, fmt.Errorf("too many ack ids: %d", len(p.AckIDs))
	}

	size := 1 + len(p.AckIDs)*4
	if len(p.AckIDs) > 0 {
		size += SessionIDSize
	}
	if p.Opcode.HasMessageID() {
		size += 4 + len(p.Payload)
	}
	out := make([]byte, 0, size)
	out = append(out, byte(len(p.AckIDs)))
	for _, id := range p.AckIDs {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], id)
		out = append(out, b[:]...)
	}
	if len(p.AckIDs) > 0 {
		out = append(out, p.AckRemoteSession[:]...)
	}
	if p.Opcode.HasMessageID() {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], p.MessageID)
		out = append(out, b[:]...)
		out = append(out, p.Payload...)
	}
	return out, nil
}

func DecodeControlPlain(opcode Opcode, plain []byte) (ackIDs []uint32, ackRemote SessionID, messageID uint32, payload []byte, err error) {
	if len(plain) < 1 {
		return nil, SessionID{}, 0, nil, errors.New("control payload too short")
	}
	ackLen := int(plain[0])
	offset := 1
	if len(plain) < offset+ackLen*4 {
		return nil, SessionID{}, 0, nil, errors.New("control ack array truncated")
	}
	ackIDs = make([]uint32, ackLen)
	for i := 0; i < ackLen; i++ {
		ackIDs[i] = binary.BigEndian.Uint32(plain[offset : offset+4])
		offset += 4
	}
	if ackLen > 0 {
		if len(plain) < offset+SessionIDSize {
			return nil, SessionID{}, 0, nil, errors.New("control ack remote session truncated")
		}
		copy(ackRemote[:], plain[offset:offset+SessionIDSize])
		offset += SessionIDSize
	}
	if opcode.HasMessageID() {
		if len(plain) < offset+4 {
			return nil, SessionID{}, 0, nil, errors.New("control message id truncated")
		}
		messageID = binary.BigEndian.Uint32(plain[offset : offset+4])
		offset += 4
		payload = cloneBytes(plain[offset:])
	} else if len(plain) != offset {
		return nil, SessionID{}, 0, nil, errors.New("ack packet has trailing payload")
	}
	return ackIDs, ackRemote, messageID, payload, nil
}

func (p ControlPacket) Encode(crypt *TLSCrypt, packetID uint32, unixTime uint32) ([]byte, error) {
	if crypt == nil {
		return nil, errors.New("tls-crypt is required")
	}
	plain, err := p.EncodePlain()
	if err != nil {
		return nil, err
	}

	header := make([]byte, TLSCryptHeaderSize)
	header[0] = opcodeKeyID(p.Opcode, p.KeyID)
	copy(header[1:], p.LocalSession[:])
	return crypt.Wrap(header, packetID, unixTime, plain)
}

func DecodeControlPacket(crypt *TLSCrypt, packet []byte) (*ControlPacket, uint32, uint32, error) {
	if crypt == nil {
		return nil, 0, 0, errors.New("tls-crypt is required")
	}
	header, packetID, unixTime, plain, err := crypt.Unwrap(packet)
	if err != nil {
		return nil, 0, 0, err
	}
	if len(header) != TLSCryptHeaderSize {
		return nil, 0, 0, fmt.Errorf("invalid control header length %d", len(header))
	}
	opcode, keyID := parseOpcodeKeyID(header[0])
	if !opcode.IsControl() {
		return nil, 0, 0, fmt.Errorf("opcode %s is not a control opcode", opcode)
	}
	var local SessionID
	copy(local[:], header[1:])

	ackIDs, ackRemote, messageID, payload, err := DecodeControlPlain(opcode, plain)
	if err != nil {
		return nil, 0, 0, err
	}
	return &ControlPacket{
		Opcode:           opcode,
		KeyID:            keyID,
		LocalSession:     local,
		AckIDs:           ackIDs,
		AckRemoteSession: ackRemote,
		MessageID:        messageID,
		Payload:          payload,
	}, packetID, unixTime, nil
}
