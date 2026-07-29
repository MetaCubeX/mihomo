package shadowquic

import (
	"encoding/binary"
	"errors"
	"io"
	"time"
)

const (
	// Private mihomo extension opcode: ASCII "mihomo" + extension id 1.
	extensionOpcodeMihomoBrutal uint64 = 0x6d69686f6d6f0001

	brutalNegotiationVersion       byte = 1
	brutalNegotiationHeaderLen          = 1 + 1 + 2 // version + flags + payload length
	brutalNegotiationMinPayloadLen      = 8         // rx
	brutalNegotiationMaxPayloadLen      = 64

	brutalNegotiationFlagRxAuto byte = 1 << 0
	brutalNegotiationTimeout         = 10 * time.Second
)

var (
	errInvalidBrutalNegotiation = errors.New("shadowquic: invalid brutal negotiation")
	errUnsupportedBrutalVersion = errors.New("shadowquic: unsupported brutal negotiation version")
)

// WriteBrutalNegotiationRequest writes a mihomo-only private extension request.
// JLS already authenticates users; rx follows Hysteria2 semantics: the desired
// receive bandwidth in bytes per second, with 0 meaning unknown/auto.
//
// The extension body uses a tiny versioned frame:
//
//	version(1) | flags(1) | payload length(2) | payload
//
// Version 1 defines the first 8 payload bytes as rx. Readers deliberately
// ignore unknown flags and payload bytes after rx so future optional fields can
// be appended without changing the extension opcode.
func WriteBrutalNegotiationRequest(w io.Writer, rx uint64) error {
	var buf [1 + 8 + brutalNegotiationHeaderLen + brutalNegotiationMinPayloadLen]byte
	buf[0] = CommandExtension
	binary.BigEndian.PutUint64(buf[1:9], extensionOpcodeMihomoBrutal)
	writeBrutalNegotiationFrame(buf[9:], 0, rx)
	_, err := w.Write(buf[:])
	return err
}

func ReadBrutalNegotiationRequest(r io.Reader) (uint64, error) {
	rx, _, err := readBrutalNegotiationFrame(r)
	return rx, err
}

func WriteBrutalNegotiationResponse(w io.Writer, rx uint64, rxAuto bool) error {
	var buf [brutalNegotiationHeaderLen + brutalNegotiationMinPayloadLen]byte
	var flags byte
	if rxAuto {
		flags |= brutalNegotiationFlagRxAuto
	}
	writeBrutalNegotiationFrame(buf[:], flags, rx)
	_, err := w.Write(buf[:])
	return err
}

func ReadBrutalNegotiationResponse(r io.Reader) (rx uint64, rxAuto bool, err error) {
	rx, flags, err := readBrutalNegotiationFrame(r)
	if err != nil {
		return 0, false, err
	}
	return rx, flags&brutalNegotiationFlagRxAuto != 0, nil
}

func writeBrutalNegotiationFrame(buf []byte, flags byte, rx uint64) {
	buf[0] = brutalNegotiationVersion
	buf[1] = flags
	binary.BigEndian.PutUint16(buf[2:4], brutalNegotiationMinPayloadLen)
	binary.BigEndian.PutUint64(buf[4:12], rx)
}

func readBrutalNegotiationFrame(r io.Reader) (rx uint64, flags byte, err error) {
	var header [brutalNegotiationHeaderLen]byte
	if _, err = io.ReadFull(r, header[:]); err != nil {
		return 0, 0, err
	}
	if header[0] != brutalNegotiationVersion {
		return 0, 0, errUnsupportedBrutalVersion
	}
	payloadLen := int(binary.BigEndian.Uint16(header[2:4]))
	if payloadLen < brutalNegotiationMinPayloadLen || payloadLen > brutalNegotiationMaxPayloadLen {
		return 0, 0, errInvalidBrutalNegotiation
	}
	payload := make([]byte, payloadLen)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, 0, err
	}
	return binary.BigEndian.Uint64(payload[:8]), header[1], nil
}
