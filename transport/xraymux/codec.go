package xraymux

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
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
	SessionID   uint16
	Status      Status
	Option      Option
	Network     Network
	Destination string
	Port        uint16
	Payload     []byte
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
	if err := validateFrame(frame); err != nil {
		return nil, protocolError("encode", err)
	}

	var metadata bytes.Buffer
	_ = binary.Write(&metadata, binary.BigEndian, frame.SessionID)
	_ = metadata.WriteByte(byte(frame.Status))
	_ = metadata.WriteByte(byte(frame.Option))
	if frame.Status == StatusNew || (frame.Status == StatusKeep && frame.Destination != "") {
		_ = metadata.WriteByte(byte(frame.Network))
		_ = binary.Write(&metadata, binary.BigEndian, frame.Port)
		if err := writeAddress(&metadata, frame.Destination); err != nil {
			return nil, protocolError("encode address", err)
		}
	}
	if metadata.Len() > MaxMetadataSize {
		return nil, protocolError("encode", fmt.Errorf("metadata length %d exceeds %d", metadata.Len(), MaxMetadataSize))
	}

	capacity := 2 + metadata.Len()
	if frame.Option&OptionData != 0 {
		capacity += 2 + len(frame.Payload)
	}
	result := bytes.NewBuffer(make([]byte, 0, capacity))
	_ = binary.Write(result, binary.BigEndian, uint16(metadata.Len()))
	_, _ = result.Write(metadata.Bytes())
	if frame.Option&OptionData != 0 {
		_ = binary.Write(result, binary.BigEndian, uint16(len(frame.Payload)))
		_, _ = result.Write(frame.Payload)
	}
	return result.Bytes(), nil
}

func DecodeFrame(r io.Reader) (Frame, error) {
	var lengthBytes [2]byte
	if _, err := io.ReadFull(r, lengthBytes[:]); err != nil {
		return Frame{}, protocolError("read metadata length", err)
	}
	metadataLen := int(binary.BigEndian.Uint16(lengthBytes[:]))
	if metadataLen < 4 || metadataLen > MaxMetadataSize {
		return Frame{}, protocolError("read metadata", fmt.Errorf("invalid metadata length %d", metadataLen))
	}
	metadata := make([]byte, metadataLen)
	if _, err := io.ReadFull(r, metadata); err != nil {
		return Frame{}, protocolError("read metadata", err)
	}

	frame := Frame{
		SessionID: binary.BigEndian.Uint16(metadata[:2]),
		Status:    Status(metadata[2]),
		Option:    Option(metadata[3]),
	}
	if frame.Status != StatusNew && frame.Status != StatusKeep && frame.Status != StatusEnd && frame.Status != StatusKeepAlive {
		return Frame{}, protocolError("decode metadata", fmt.Errorf("invalid status %d", frame.Status))
	}
	if frame.Option & ^(OptionData|OptionError) != 0 {
		return Frame{}, protocolError("decode metadata", fmt.Errorf("invalid option %d", frame.Option))
	}

	targetBytes := metadata[4:]
	if frame.Status == StatusNew || len(targetBytes) > 0 {
		if len(targetBytes) < 4 {
			return Frame{}, protocolError("decode target", io.ErrUnexpectedEOF)
		}
		frame.Network = Network(targetBytes[0])
		if frame.Network != NetworkTCP && frame.Network != NetworkUDP {
			return Frame{}, protocolError("decode target", fmt.Errorf("invalid network %d", frame.Network))
		}
		frame.Port = binary.BigEndian.Uint16(targetBytes[1:3])
		host, consumed, err := readAddress(targetBytes[3:])
		if err != nil {
			return Frame{}, protocolError("decode target", err)
		}
		if 3+consumed != len(targetBytes) {
			return Frame{}, protocolError("decode target", fmt.Errorf("unexpected trailing metadata: %d bytes", len(targetBytes)-3-consumed))
		}
		frame.Destination = host
	}

	if frame.Option&OptionData != 0 {
		if _, err := io.ReadFull(r, lengthBytes[:]); err != nil {
			return Frame{}, protocolError("read payload length", err)
		}
		payloadLen := int(binary.BigEndian.Uint16(lengthBytes[:]))
		frame.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, frame.Payload); err != nil {
			return Frame{}, protocolError("read payload", err)
		}
	}
	return frame, nil
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
	if frame.Status == StatusNew || (frame.Status == StatusKeep && frame.Destination != "") {
		if frame.Network != NetworkTCP && frame.Network != NetworkUDP {
			return fmt.Errorf("invalid network %d", frame.Network)
		}
		if frame.Destination == "" {
			return errors.New("empty destination")
		}
	}
	return nil
}

func writeAddress(dst *bytes.Buffer, host string) error {
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		_ = dst.WriteByte(addressIPv4)
		_, _ = dst.Write(ip4)
		return nil
	}
	if ip16 := ip.To16(); ip16 != nil {
		_ = dst.WriteByte(addressIPv6)
		_, _ = dst.Write(ip16)
		return nil
	}
	if len(host) == 0 || len(host) > 255 {
		return fmt.Errorf("invalid domain length %d", len(host))
	}
	_ = dst.WriteByte(addressDomain)
	_ = dst.WriteByte(byte(len(host)))
	_, _ = dst.WriteString(host)
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
