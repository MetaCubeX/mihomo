package openvpn

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/rasky/go-lzo"
)

// OpenVPN compression framing modes (compress directive, OpenVPN 2.4+).
//
// The "compress" directive uses a 1-byte compression byte prefix on each
// data channel packet:
//
//   0x00  - uncompressed (plain)
//   0x40  - LZO compressed (comp-lzo)
//   0x50  - compression stub (no actual compression, just framing)
//   0x69  - LZ4 compressed
//   0x6A  - LZ4-v2 compressed
//
// "stub-v2" uses a slightly different encoding: the byte is 0x50, and if
// the first byte of the plaintext is 0x00, it is doubled to distinguish
// from the "uncompressed" case.
const (
	compressByteUncompressed = 0x00
	compressByteLZO          = 0x40
	compressByteStub         = 0x50
	compressByteLZ4          = 0x69
	compressByteLZ4v2        = 0x6A
)

// CompressionMode represents the OpenVPN compression framing mode.
type CompressionMode int

const (
	// CompressionNone means no compression framing at all.
	CompressionNone CompressionMode = iota
	// CompressionLZO is the legacy comp-lzo mode.
	CompressionLZO
	// CompressionStub adds a stub byte without actual compression.
	CompressionStub
	// CompressionStubV2 adds a stub-v2 byte without actual compression.
	CompressionStubV2
	// CompressionLZ4 uses LZ4 compression with compress framing.
	CompressionLZ4
	// CompressionLZ4v2 uses LZ4-v2 compression.
	CompressionLZ4v2
)

// AllowCompressionPolicy controls how the client handles compression.
type AllowCompressionPolicy int

const (
	// AllowCompressionNo permits only stub framing; no actual compression.
	AllowCompressionNo AllowCompressionPolicy = iota
	// AllowCompressionAsym accepts compressed packets from the server but
	// does not compress outgoing packets.
	AllowCompressionAsym
	// AllowCompressionYes permits compression in both directions.
	AllowCompressionYes
)

// ParseCompressionMode parses the "compress" directive value.
func ParseCompressionMode(mode string) (CompressionMode, error) {
	switch normalizeLower(mode) {
	case "", "off", "disabled":
		return CompressionNone, nil
	case "none":
		return CompressionNone, nil
	case "no":
		return CompressionStub, nil
	case "stub":
		return CompressionStub, nil
	case "stub-v2":
		return CompressionStubV2, nil
	case "lz4":
		return CompressionLZ4, nil
	case "lz4-v2":
		return CompressionLZ4v2, nil
	default:
		return CompressionNone, fmt.Errorf("unsupported compress mode %q", mode)
	}
}

// ParseAllowCompression parses the "allow-compression" directive value.
func ParseAllowCompression(policy string) (AllowCompressionPolicy, error) {
	switch normalizeLower(policy) {
	case "", "no":
		return AllowCompressionNo, nil
	case "asym":
		return AllowCompressionAsym, nil
	case "yes":
		return AllowCompressionYes, nil
	default:
		return AllowCompressionNo, fmt.Errorf("unsupported allow-compression %q", policy)
	}
}

// Compressor handles OpenVPN data channel compression framing.
type Compressor struct {
	mode            CompressionMode
	allowCompressed AllowCompressionPolicy
}

// NewCompressor creates a compressor with the given mode and policy.
func NewCompressor(mode CompressionMode, policy AllowCompressionPolicy) *Compressor {
	return &Compressor{
		mode:            mode,
		allowCompressed: policy,
	}
}

// Mode returns the compression mode.
func (c *Compressor) Mode() CompressionMode { return c.mode }

// ShouldCompress returns true if outgoing packets should be compressed.
func (c *Compressor) ShouldCompress() bool {
	if c == nil {
		return false
	}
	switch c.mode {
	case CompressionLZO, CompressionLZ4, CompressionLZ4v2:
		return c.allowCompressed == AllowCompressionYes
	default:
		return false
	}
}

// CompressFrame adds compression framing to an outgoing packet.
// Even for stub modes, the framing byte is prepended.
func (c *Compressor) CompressFrame(packet []byte) ([]byte, error) {
	if c == nil || c.mode == CompressionNone {
		return packet, nil
	}

	switch c.mode {
	case CompressionStub:
		// Stub: prepend 0x50 byte.
		out := make([]byte, 1+len(packet))
		out[0] = compressByteStub
		copy(out[1:], packet)
		return out, nil

	case CompressionStubV2:
		// Stub-v2: prepend 0x50 byte. If the first byte of the payload
		// is 0x00, prepend an extra 0x00 to disambiguate from uncompressed.
		if len(packet) > 0 && packet[0] == 0x00 {
			out := make([]byte, 2+len(packet))
			out[0] = compressByteStub
			out[1] = 0x00
			copy(out[2:], packet)
			return out, nil
		}
		out := make([]byte, 1+len(packet))
		out[0] = compressByteStub
		copy(out[1:], packet)
		return out, nil

	case CompressionLZ4:
		if c.allowCompressed != AllowCompressionYes {
			// Not compressing, but still need stub framing.
			out := make([]byte, 1+len(packet))
			out[0] = compressByteStub
			copy(out[1:], packet)
			return out, nil
		}
		// LZ4 compression would require a LZ4 library.
		// For now, send uncompressed with LZ4 framing marker.
		out := make([]byte, 1+len(packet))
		out[0] = compressByteUncompressed
		copy(out[1:], packet)
		return out, nil

	case CompressionLZ4v2:
		if c.allowCompressed != AllowCompressionYes {
			out := make([]byte, 1+len(packet))
			out[0] = compressByteStub
			copy(out[1:], packet)
			return out, nil
		}
		out := make([]byte, 1+len(packet))
		out[0] = compressByteUncompressed
		copy(out[1:], packet)
		return out, nil

	case CompressionLZO:
		// LZO compression via comp-lzo is handled separately by the legacy
		// comp-lzo path in the client. This path should not be reached.
		return packet, nil

	default:
		return packet, nil
	}
}

// DecompressFrame removes compression framing from an incoming packet.
func (c *Compressor) DecompressFrame(packet []byte) ([]byte, error) {
	if c == nil || c.mode == CompressionNone || len(packet) == 0 {
		return packet, nil
	}

	switch c.mode {
	case CompressionStub:
		if packet[0] != compressByteStub {
			return nil, fmt.Errorf("unexpected compression byte 0x%02x for stub mode", packet[0])
		}
		return packet[1:], nil

	case CompressionStubV2:
		if packet[0] != compressByteStub {
			return nil, fmt.Errorf("unexpected compression byte 0x%02x for stub-v2 mode", packet[0])
		}
		// In stub-v2, if the payload started with 0x00, an extra 0x00 was
		// inserted after the stub byte. We need to remove it.
		if len(packet) > 1 && packet[1] == 0x00 {
			// Remove the stub byte AND the disambiguation byte.
			return packet[2:], nil
		}
		// No disambiguation byte; just remove the stub byte.
		return packet[1:], nil

	case CompressionLZ4, CompressionLZ4v2:
		if len(packet) < 1 {
			return nil, errors.New("empty compressed packet")
		}
		switch packet[0] {
		case compressByteUncompressed:
			return packet[1:], nil
		case compressByteLZ4, compressByteLZ4v2:
			if c.allowCompressed == AllowCompressionNo {
				return nil, errors.New("received LZ4 compressed packet but allow-compression is no")
			}
			// LZ4 decompression would require a LZ4 library.
			// For now, return an error.
			return nil, errors.New("LZ4 decompression not yet supported")
		case compressByteStub:
			return packet[1:], nil
		default:
			return nil, fmt.Errorf("unexpected compression byte 0x%02x", packet[0])
		}

	case CompressionLZO:
		// LZO via compress framing.
		if len(packet) < 1 {
			return nil, errors.New("empty LZO packet")
		}
		switch packet[0] {
		case compressByteUncompressed:
			return packet[1:], nil
		case compressByteLZO:
			if c.allowCompressed == AllowCompressionNo {
				return nil, errors.New("received LZO compressed packet but allow-compression is no")
			}
			if len(packet) < 2 {
				return nil, nil
			}
			out, err := lzoDecompress(packet[1:])
			if err != nil {
				return nil, fmt.Errorf("LZO decompression: %w", err)
			}
			return out, nil
		case compressByteStub:
			return packet[1:], nil
		default:
			return nil, fmt.Errorf("unexpected compression byte 0x%02x for LZO mode", packet[0])
		}

	default:
		return packet, nil
	}
}

// lzoDecompress decompresses LZO1X data.
func lzoDecompress(src []byte) ([]byte, error) {
	r := bytes.NewReader(src)
	out, err := lzo.Decompress1X(r, len(src), 0)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func normalizeLower(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
