package openvpn

import (
	"errors"
	"fmt"
	"strings"

	"github.com/pierrec/lz4/v4"
)

const (
	openVPNLZOCompressByte    = 0x66
	openVPNLZ4CompressByte    = 0x69
	openVPNNoCompressByte     = 0xfa
	openVPNNoCompressByteSwap = 0xfb
	openVPNCompressV2Byte     = 0x50
	openVPNCompressV2None     = 0x00
	openVPNCompressV2LZ4      = 0x01
	openVPNLZ4MaxOutput       = 1 << 16
	openVPNCompressThreshold  = 100
)

type CompressionMode int

const (
	CompressionNone CompressionMode = iota
	CompressionLZO
	CompressionStub
	CompressionStubV2
	CompressionLZ4
	CompressionLZ4v2
)

type AllowCompressionPolicy int

const (
	AllowCompressionNo AllowCompressionPolicy = iota
	AllowCompressionAsym
	AllowCompressionYes
)

func ParseCompressionMode(mode string) (CompressionMode, error) {
	switch normalizeLower(mode) {
	case "", "none", "off", "disabled":
		return CompressionNone, nil
	case "no", "stub":
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

type Compressor struct {
	mode            CompressionMode
	allowCompressed AllowCompressionPolicy
}

func NewCompressor(mode CompressionMode, policy AllowCompressionPolicy) *Compressor {
	return &Compressor{mode: mode, allowCompressed: policy}
}

func (c *Compressor) Mode() CompressionMode { return c.mode }

func (c *Compressor) PayloadOverhead() int {
	if c == nil {
		return 0
	}
	switch c.mode {
	case CompressionLZO, CompressionStub, CompressionLZ4:
		return 1
	case CompressionStubV2, CompressionLZ4v2:
		return 2
	default:
		return 0
	}
}

func (c *Compressor) ShouldCompress() bool {
	return c != nil && c.allowCompressed == AllowCompressionYes &&
		(c.mode == CompressionLZO || c.mode == CompressionLZ4 || c.mode == CompressionLZ4v2)
}

func (c *Compressor) CompressFrame(payload []byte) ([]byte, error) {
	if c == nil || c.mode == CompressionNone {
		return append([]byte(nil), payload...), nil
	}
	switch c.mode {
	case CompressionStub:
		return applyV1SwapFrame(payload), nil
	case CompressionStubV2:
		return escapeV2Stub(payload), nil
	case CompressionLZ4:
		if c.allowCompressed == AllowCompressionYes && len(payload) >= openVPNCompressThreshold {
			if block, ok, err := compressLZ4Block(payload); err != nil {
				return nil, err
			} else if ok && len(block) < len(payload) {
				return applyV1LZ4Frame(block), nil
			}
		}
		return applyV1SwapFrame(payload), nil
	case CompressionLZ4v2:
		if c.allowCompressed == AllowCompressionYes && len(payload) >= openVPNCompressThreshold {
			if block, ok, err := compressLZ4Block(payload); err != nil {
				return nil, err
			} else if ok && len(block)+2 < len(payload) {
				out := make([]byte, 2+len(block))
				out[0], out[1] = openVPNCompressV2Byte, openVPNCompressV2LZ4
				copy(out[2:], block)
				return out, nil
			}
		}
		return escapeV2Stub(payload), nil
	case CompressionLZO:
		return lzo1xCompressSafe(payload)
	default:
		return nil, errors.New("invalid compression mode")
	}
}

func (c *Compressor) DecompressFrame(payload []byte) ([]byte, error) {
	if c == nil || c.mode == CompressionNone {
		return append([]byte(nil), payload...), nil
	}
	if len(payload) == 0 {
		return nil, errors.New("missing compression marker")
	}
	switch c.mode {
	case CompressionStub:
		if payload[0] != openVPNNoCompressByteSwap {
			return nil, fmt.Errorf("invalid compression stub marker 0x%02x", payload[0])
		}
		return unswapV1Frame(payload), nil
	case CompressionStubV2:
		return unwrapV2Frame(payload, false, c.allowCompressed)
	case CompressionLZ4:
		switch payload[0] {
		case openVPNNoCompressByte:
			return append([]byte(nil), payload[1:]...), nil
		case openVPNNoCompressByteSwap:
			return unswapV1Frame(payload), nil
		case openVPNLZ4CompressByte:
			if c.allowCompressed == AllowCompressionNo {
				return nil, errors.New("received LZ4 packet while compression is forbidden")
			}
			return decompressLZ4Block(restoreV1LZ4Block(payload))
		default:
			return nil, fmt.Errorf("invalid LZ4 v1 marker 0x%02x", payload[0])
		}
	case CompressionLZ4v2:
		return unwrapV2Frame(payload, true, c.allowCompressed)
	case CompressionLZO:
		return lzo1xDecompressSafe(payload)
	default:
		return nil, errors.New("invalid compression mode")
	}
}

func applyV1SwapFrame(payload []byte) []byte {
	if len(payload) == 0 {
		return []byte{openVPNNoCompressByteSwap}
	}
	out := make([]byte, len(payload)+1)
	out[0] = openVPNNoCompressByteSwap
	copy(out[1:], payload[1:])
	out[len(payload)] = payload[0]
	return out
}

func unswapV1Frame(frame []byte) []byte {
	if len(frame) <= 1 {
		return []byte{}
	}
	n := len(frame) - 1
	out := make([]byte, n)
	out[0] = frame[n]
	copy(out[1:], frame[1:n])
	return out
}

func applyV1LZ4Frame(block []byte) []byte {
	out := make([]byte, len(block)+1)
	out[0] = openVPNLZ4CompressByte
	copy(out[1:], block[1:])
	out[len(block)] = block[0]
	return out
}

func restoreV1LZ4Block(frame []byte) []byte {
	if len(frame) <= 1 {
		return nil
	}
	n := len(frame) - 1
	out := make([]byte, n)
	out[0] = frame[n]
	copy(out[1:], frame[1:n])
	return out
}

func escapeV2Stub(payload []byte) []byte {
	if len(payload) == 0 || payload[0] != openVPNCompressV2Byte {
		return append([]byte(nil), payload...)
	}
	out := make([]byte, len(payload)+2)
	out[0], out[1] = openVPNCompressV2Byte, openVPNCompressV2None
	copy(out[2:], payload)
	return out
}

func unwrapV2Frame(payload []byte, allowLZ4 bool, policy AllowCompressionPolicy) ([]byte, error) {
	if len(payload) == 0 || payload[0] != openVPNCompressV2Byte {
		return append([]byte(nil), payload...), nil
	}
	if len(payload) < 2 {
		return nil, errors.New("truncated compression v2 header")
	}
	switch payload[1] {
	case openVPNCompressV2None:
		return append([]byte(nil), payload[2:]...), nil
	case openVPNCompressV2LZ4:
		if !allowLZ4 || policy == AllowCompressionNo {
			return nil, errors.New("received unsupported LZ4 v2 payload")
		}
		return decompressLZ4Block(payload[2:])
	default:
		return nil, fmt.Errorf("invalid compression v2 subtype 0x%02x", payload[1])
	}
}

func compressLZ4Block(payload []byte) ([]byte, bool, error) {
	out := make([]byte, lz4.CompressBlockBound(len(payload)))
	n, err := lz4.CompressBlock(payload, out, nil)
	if err != nil {
		return nil, false, err
	}
	if n == 0 {
		return nil, false, nil
	}
	return out[:n], true, nil
}

func decompressLZ4Block(block []byte) ([]byte, error) {
	if len(block) == 0 {
		return nil, errors.New("empty LZ4 block")
	}
	out := make([]byte, openVPNLZ4MaxOutput)
	n, err := lz4.UncompressBlock(block, out)
	if err != nil || n <= 0 {
		return nil, errors.New("LZ4 block decompression failed")
	}
	return out[:n], nil
}

func normalizeLower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
