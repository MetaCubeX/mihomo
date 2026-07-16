package xraymux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/common/pool"
)

const (
	MaxMetadataSize = 512
	MaxPayloadSize  = 8 * 1024
)

type Status byte

const (
	StatusNew       Status = 0x01
	StatusKeep      Status = 0x02
	StatusEnd       Status = 0x03
	StatusKeepAlive Status = 0x04
)

type Option byte

const (
	OptionData  Option = 0x01
	OptionError Option = 0x02
)

type Network byte

const (
	NetworkTCP Network = 0x01
	NetworkUDP Network = 0x02
)

const (
	addressIPv4   byte = 0x01
	addressDomain byte = 0x02
	addressIPv6   byte = 0x03
)

type Frame struct {
	SessionID     uint16
	Status        Status
	Option        Option
	Network       Network
	Destination   string
	DestinationIP netip.Addr
	Port          uint16
	GlobalID      [8]byte
	Payload       []byte
}

type decodedFrame struct {
	Frame
	payloadPooled bool
}

type ProtocolError struct {
	Op  string
	Err error
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("xray mux %s: %v", e.Op, e.Err)
}

func (e *ProtocolError) Unwrap() error {
	return e.Err
}

func protocolError(op string, err error) error {
	return &ProtocolError{Op: op, Err: err}
}

func EncodeFrame(frame Frame) ([]byte, error) {
	return encodeFrame(nil, frame)
}

func encodeFrame(buffer []byte, frame Frame) ([]byte, error) {
	if frame.Status == StatusKeep &&
		frame.Option == OptionData &&
		frame.Network == 0 &&
		frame.Destination == "" &&
		!frame.DestinationIP.IsValid() &&
		frame.Port == 0 &&
		frame.GlobalID == [8]byte{} &&
		len(frame.Payload) <= int(^uint16(0)) {
		return encodeKeepDataFrame(buffer, frame.SessionID, frame.Payload), nil
	}
	if err := validateFrame(frame); err != nil {
		return nil, protocolError("encode", err)
	}

	hasTarget := frame.Status == StatusNew || (frame.Status == StatusKeep && (frame.Destination != "" || frame.DestinationIP.IsValid()))
	metadataLen := 4
	targetAddr := frame.DestinationIP.Unmap()
	if hasTarget {
		metadataLen += 3
		if targetAddr.IsValid() && targetAddr.Zone() != "" {
			return nil, protocolError("encode address", errors.New("scoped IPv6 addresses are not supported"))
		}
		if parsed, ok := parseLiteralIP(frame.Destination); !targetAddr.IsValid() && ok {
			targetAddr = parsed.Unmap()
		}
		if targetAddr.IsValid() {
			if targetAddr.Is4() {
				metadataLen += 1 + net.IPv4len
			} else {
				metadataLen += 1 + net.IPv6len
			}
		} else {
			if len(frame.Destination) == 0 || len(frame.Destination) > 255 {
				return nil, protocolError("encode address", fmt.Errorf("invalid domain length %d", len(frame.Destination)))
			}
			metadataLen += 2 + len(frame.Destination)
		}
	}
	if frame.Status == StatusNew && frame.Network == NetworkUDP && frame.Option&OptionData != 0 {
		metadataLen += len(frame.GlobalID)
	}
	if metadataLen > MaxMetadataSize {
		return nil, protocolError("encode", fmt.Errorf("metadata length %d exceeds %d", metadataLen, MaxMetadataSize))
	}

	frameLen := 2 + metadataLen
	if frame.Option&OptionData != 0 {
		frameLen += 2 + len(frame.Payload)
	}
	var result []byte
	if cap(buffer) >= frameLen {
		result = buffer[:frameLen]
	} else {
		result = make([]byte, frameLen)
	}
	binary.BigEndian.PutUint16(result, uint16(metadataLen))
	offset := 2
	binary.BigEndian.PutUint16(result[offset:], frame.SessionID)
	offset += 2
	result[offset] = byte(frame.Status)
	offset++
	result[offset] = byte(frame.Option)
	offset++
	if hasTarget {
		result[offset] = byte(frame.Network)
		offset++
		binary.BigEndian.PutUint16(result[offset:], frame.Port)
		offset += 2
		if targetAddr.IsValid() {
			if targetAddr.Is4() {
				result[offset] = addressIPv4
				offset++
				address := targetAddr.As4()
				offset += copy(result[offset:], address[:])
			} else {
				result[offset] = addressIPv6
				offset++
				address := targetAddr.As16()
				offset += copy(result[offset:], address[:])
			}
		} else {
			result[offset] = addressDomain
			result[offset+1] = byte(len(frame.Destination))
			offset += 2
			offset += copy(result[offset:], frame.Destination)
		}
	}
	if frame.Status == StatusNew && frame.Network == NetworkUDP && frame.Option&OptionData != 0 {
		offset += copy(result[offset:], frame.GlobalID[:])
	}
	if frame.Option&OptionData != 0 {
		binary.BigEndian.PutUint16(result[offset:], uint16(len(frame.Payload)))
		offset += 2
		copy(result[offset:], frame.Payload)
	}
	return result, nil
}

func encodeKeepDataFrame(buffer []byte, sessionID uint16, payload []byte) []byte {
	frameLen := 8 + len(payload)
	var result []byte
	if cap(buffer) >= frameLen {
		result = buffer[:frameLen]
	} else {
		result = make([]byte, frameLen)
	}
	binary.BigEndian.PutUint16(result, 4)
	binary.BigEndian.PutUint16(result[2:], sessionID)
	result[4] = byte(StatusKeep)
	result[5] = byte(OptionData)
	binary.BigEndian.PutUint16(result[6:], uint16(len(payload)))
	copy(result[8:], payload)
	return result
}

func parseLiteralIP(host string) (netip.Addr, bool) {
	if host == "" {
		return netip.Addr{}, false
	}
	first := host[0]
	if (first < '0' || first > '9') && strings.IndexByte(host, ':') < 0 {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func DecodeFrame(r io.Reader) (Frame, error) {
	return decodeFrame(r, nil)
}

func decodeFrame(r io.Reader, metadataBuffer []byte) (Frame, error) {
	decoded, err := decodeFrameWithPayloadPool(r, metadataBuffer, false)
	return decoded.Frame, err
}

func decodeFramePooled(r io.Reader, metadataBuffer []byte) (decodedFrame, error) {
	return decodeFrameWithPayloadPool(r, metadataBuffer, true)
}

func decodeFrameWithPayloadPool(r io.Reader, metadataBuffer []byte, poolPayload bool) (decodedFrame, error) {
	var lengthBytes []byte
	if len(metadataBuffer) >= 2 {
		lengthBytes = metadataBuffer[:2]
	} else {
		lengthBytes = make([]byte, 2)
	}
	if _, err := io.ReadFull(r, lengthBytes); err != nil {
		return decodedFrame{}, protocolError("read metadata length", err)
	}
	metadataLen := int(binary.BigEndian.Uint16(lengthBytes))
	if metadataLen < 4 || metadataLen > MaxMetadataSize {
		return decodedFrame{}, protocolError("read metadata", fmt.Errorf("invalid metadata length %d", metadataLen))
	}
	var metadata []byte
	if len(metadataBuffer) >= metadataLen {
		metadata = metadataBuffer[:metadataLen]
	} else {
		metadata = make([]byte, metadataLen)
	}
	if _, err := io.ReadFull(r, metadata); err != nil {
		return decodedFrame{}, protocolError("read metadata", err)
	}

	frame := Frame{
		SessionID: binary.BigEndian.Uint16(metadata[:2]),
		Status:    Status(metadata[2]),
		Option:    Option(metadata[3]),
	}
	fastKeepData := metadataLen == 4 && frame.Status == StatusKeep && frame.Option == OptionData
	if !fastKeepData {
		if frame.Status != StatusNew && frame.Status != StatusKeep && frame.Status != StatusEnd && frame.Status != StatusKeepAlive {
			return decodedFrame{}, protocolError("decode metadata", fmt.Errorf("invalid status %d", frame.Status))
		}
		if frame.Option & ^(OptionData|OptionError) != 0 {
			return decodedFrame{}, protocolError("decode metadata", fmt.Errorf("invalid option %d", frame.Option))
		}

		targetBytes := metadata[4:]
		hasTarget := frame.Status == StatusNew || (frame.Status == StatusKeep && len(targetBytes) > 0)
		if len(targetBytes) > 0 && !hasTarget {
			return decodedFrame{}, protocolError("decode metadata", fmt.Errorf("unexpected trailing metadata: %d bytes", len(targetBytes)))
		}
		if hasTarget {
			if len(targetBytes) < 4 {
				return decodedFrame{}, protocolError("decode target", io.ErrUnexpectedEOF)
			}
			frame.Network = Network(targetBytes[0])
			if frame.Network != NetworkTCP && frame.Network != NetworkUDP {
				return decodedFrame{}, protocolError("decode target", fmt.Errorf("invalid network %d", frame.Network))
			}
			if frame.Status == StatusKeep && frame.Network != NetworkUDP {
				return decodedFrame{}, protocolError("decode target", errors.New("follow-up target is only valid for UDP"))
			}
			frame.Port = binary.BigEndian.Uint16(targetBytes[1:3])
			host, consumed, err := readAddress(targetBytes[3:])
			if err != nil {
				return decodedFrame{}, protocolError("decode target", err)
			}
			frame.Destination = host
			targetBytes = targetBytes[3+consumed:]
			if frame.Status == StatusNew && frame.Network == NetworkUDP && frame.Option&OptionData != 0 {
				if len(targetBytes) != len(frame.GlobalID) {
					return decodedFrame{}, protocolError("decode GlobalID", fmt.Errorf("invalid length %d", len(targetBytes)))
				}
				copy(frame.GlobalID[:], targetBytes)
				targetBytes = nil
			}
			if len(targetBytes) != 0 {
				return decodedFrame{}, protocolError("decode target", fmt.Errorf("unexpected trailing metadata: %d bytes", len(targetBytes)))
			}
		}
	}

	if frame.Option&OptionData != 0 {
		if _, err := io.ReadFull(r, lengthBytes); err != nil {
			return decodedFrame{}, protocolError("read payload length", err)
		}
		payloadLen := int(binary.BigEndian.Uint16(lengthBytes))
		payloadPooled := false
		if poolPayload && payloadLen > 0 {
			frame.Payload = pool.Get(payloadLen)[:payloadLen]
			payloadPooled = true
		} else {
			frame.Payload = make([]byte, payloadLen)
		}
		if _, err := io.ReadFull(r, frame.Payload); err != nil {
			decoded := decodedFrame{Frame: frame, payloadPooled: payloadPooled}
			decoded.releasePayload()
			return decodedFrame{}, protocolError("read payload", err)
		}
		return decodedFrame{Frame: frame, payloadPooled: payloadPooled}, nil
	}
	return decodedFrame{Frame: frame}, nil
}

func (f *decodedFrame) releasePayload() {
	if !f.payloadPooled {
		return
	}
	_ = pool.Put(f.Payload)
	f.Payload = nil
	f.payloadPooled = false
}

func validateFrame(frame Frame) error {
	switch frame.Status {
	case StatusNew, StatusKeep, StatusEnd, StatusKeepAlive:
	default:
		return fmt.Errorf("invalid status %d", frame.Status)
	}
	if frame.Option & ^(OptionData|OptionError) != 0 {
		return fmt.Errorf("invalid option %d", frame.Option)
	}
	if len(frame.Payload) > int(^uint16(0)) {
		return fmt.Errorf("payload length %d exceeds uint16", len(frame.Payload))
	}
	if len(frame.Payload) > 0 && frame.Option&OptionData == 0 {
		return errors.New("payload provided without data option")
	}
	if frame.GlobalID != [8]byte{} && (frame.Status != StatusNew || frame.Network != NetworkUDP || frame.Option&OptionData == 0) {
		return errors.New("GlobalID is only valid on an initial UDP data frame")
	}
	hasTarget := frame.Destination != "" || frame.DestinationIP.IsValid()
	if frame.Status == StatusNew || (frame.Status == StatusKeep && hasTarget) {
		if frame.Network != NetworkTCP && frame.Network != NetworkUDP {
			return fmt.Errorf("invalid network %d", frame.Network)
		}
		if !hasTarget {
			return errors.New("empty destination")
		}
		if frame.Status == StatusKeep && frame.Network != NetworkUDP {
			return errors.New("follow-up target is only valid for UDP")
		}
	}
	return nil
}

func readAddress(raw []byte) (string, int, error) {
	if len(raw) < 1 {
		return "", 0, io.ErrUnexpectedEOF
	}
	switch raw[0] {
	case addressIPv4:
		if len(raw) < 1+net.IPv4len {
			return "", 0, io.ErrUnexpectedEOF
		}
		return net.IP(raw[1 : 1+net.IPv4len]).String(), 1 + net.IPv4len, nil
	case addressIPv6:
		if len(raw) < 1+net.IPv6len {
			return "", 0, io.ErrUnexpectedEOF
		}
		return net.IP(raw[1 : 1+net.IPv6len]).String(), 1 + net.IPv6len, nil
	case addressDomain:
		if len(raw) < 2 {
			return "", 0, io.ErrUnexpectedEOF
		}
		length := int(raw[1])
		if length == 0 || len(raw) < 2+length {
			return "", 0, io.ErrUnexpectedEOF
		}
		return string(raw[2 : 2+length]), 2 + length, nil
	default:
		return "", 0, fmt.Errorf("invalid address type %d", raw[0])
	}
}

func writeStreamData(w io.Writer, sessionID uint16, destination string, port uint16, initial bool, payload []byte) error {
	first := initial
	for len(payload) > 0 {
		chunkSize := len(payload)
		if chunkSize > MaxPayloadSize {
			chunkSize = MaxPayloadSize
		}
		status := StatusKeep
		frame := Frame{SessionID: sessionID, Status: status, Option: OptionData, Payload: payload[:chunkSize]}
		if first {
			frame.Status = StatusNew
			frame.Network = NetworkTCP
			frame.Destination = destination
			frame.Port = port
			first = false
		}
		encoded, err := EncodeFrame(frame)
		if err != nil {
			return err
		}
		if err := writeFull(w, encoded); err != nil {
			return err
		}
		payload = payload[chunkSize:]
	}
	return nil
}

func writeFull(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := w.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}
