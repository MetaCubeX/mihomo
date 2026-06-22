package openvpn

import (
	"context"
	"fmt"
	"strings"
)

const (
	ScrambleNone ScrambleMethod = iota
	ScrambleXORMask
	ScrambleXORPtrPos
	ScrambleReverse
	ScrambleObfuscate
)

type ScrambleMethod uint8

type ScrambleConfig struct {
	Method ScrambleMethod
	Mask   []byte
}

func (s ScrambleConfig) String() string {
	switch s.Method {
	case ScrambleNone:
		return "none"
	case ScrambleXORMask:
		return "xormask"
	case ScrambleXORPtrPos:
		return "xorptrpos"
	case ScrambleReverse:
		return "reverse"
	case ScrambleObfuscate:
		return "obfuscate"
	default:
		return fmt.Sprintf("unknown(%d)", s.Method)
	}
}

func ParseScramble(value string) (ScrambleConfig, error) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ScrambleConfig{}, nil
	}
	switch fields[0] {
	case "xormask":
		if len(fields) != 2 {
			return ScrambleConfig{}, errorsfScramble(value)
		}
		return ScrambleConfig{Method: ScrambleXORMask, Mask: []byte(fields[1])}, nil
	case "xorptrpos":
		if len(fields) != 1 {
			return ScrambleConfig{}, errorsfScramble(value)
		}
		return ScrambleConfig{Method: ScrambleXORPtrPos}, nil
	case "reverse":
		if len(fields) != 1 {
			return ScrambleConfig{}, errorsfScramble(value)
		}
		return ScrambleConfig{Method: ScrambleReverse}, nil
	case "obfuscate":
		if len(fields) != 2 {
			return ScrambleConfig{}, errorsfScramble(value)
		}
		return ScrambleConfig{Method: ScrambleObfuscate, Mask: []byte(fields[1])}, nil
	default:
		if len(fields) != 1 {
			return ScrambleConfig{}, errorsfScramble(value)
		}
		return ScrambleConfig{Method: ScrambleXORMask, Mask: []byte(fields[0])}, nil
	}
}

func errorsfScramble(value string) error {
	return fmt.Errorf("unsupported openvpn scramble %q", value)
}

func NewScramblePacketIO(io PacketIO, scramble ScrambleConfig) PacketIO {
	if scramble.Method == ScrambleNone {
		return io
	}
	return &scramblePacketIO{PacketIO: io, scramble: scramble}
}

type scramblePacketIO struct {
	PacketIO
	scramble ScrambleConfig
}

func (s *scramblePacketIO) ReadPacket(ctx context.Context) ([]byte, error) {
	packet, err := s.PacketIO.ReadPacket(ctx)
	if err != nil {
		return nil, err
	}
	packet = cloneBytes(packet)
	s.scramble.read(packet)
	return packet, nil
}

func (s *scramblePacketIO) WritePacket(ctx context.Context, packet []byte) error {
	packet = cloneBytes(packet)
	s.scramble.write(packet)
	return s.PacketIO.WritePacket(ctx, packet)
}

func (s ScrambleConfig) read(packet []byte) {
	switch s.Method {
	case ScrambleXORMask:
		bufferMask(packet, s.Mask)
	case ScrambleXORPtrPos:
		bufferXORPtrPos(packet)
	case ScrambleReverse:
		bufferReverse(packet)
	case ScrambleObfuscate:
		bufferMask(packet, s.Mask)
		bufferXORPtrPos(packet)
		bufferReverse(packet)
		bufferXORPtrPos(packet)
	}
}

func (s ScrambleConfig) write(packet []byte) {
	switch s.Method {
	case ScrambleXORMask:
		bufferMask(packet, s.Mask)
	case ScrambleXORPtrPos:
		bufferXORPtrPos(packet)
	case ScrambleReverse:
		bufferReverse(packet)
	case ScrambleObfuscate:
		bufferXORPtrPos(packet)
		bufferReverse(packet)
		bufferXORPtrPos(packet)
		bufferMask(packet, s.Mask)
	}
}

func bufferMask(packet, mask []byte) {
	if len(mask) == 0 {
		return
	}
	for i := range packet {
		packet[i] ^= mask[i%len(mask)]
	}
}

func bufferXORPtrPos(packet []byte) {
	for i := range packet {
		packet[i] ^= byte(i + 1)
	}
}

func bufferReverse(packet []byte) {
	for i, j := 1, len(packet)-1; i < j; i, j = i+1, j-1 {
		packet[i], packet[j] = packet[j], packet[i]
	}
}

var _ PacketIO = (*scramblePacketIO)(nil)
