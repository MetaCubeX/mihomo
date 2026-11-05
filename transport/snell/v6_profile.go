package snell

import (
	"encoding/binary"
	"math/bits"

	"golang.org/x/crypto/blake2b"
)

// Snell v6 derives a deployment specific "profile" from the PSK. The profile
// decides how the salt is scattered inside the first block, how long the
// per-record prefix and padding are, how padding bytes look and how padding is
// interleaved with the ciphertext. Both peers derive the same profile, so every
// value below must be computed exactly the same way as the official
// implementation. The constants and the derivation order follow the protocol
// notes published by SagerNet/sing-snell (GPL-3.0-or-later), which reference
// the corresponding routines in Surge 6.7.0 (11520).

const (
	v6GoldenGamma = 0x9e3779b97f4a7c15

	v6LabelPadding       = 0
	v6LabelBitPercent    = 1
	v6LabelMotif         = 2
	v6LabelMixOffset     = 3
	v6LabelSalt          = 3
	v6LabelProfileID     = 5
	v6LabelGenerator     = 6
	v6LabelPadMin        = 7
	v6LabelPadMax        = 8
	v6LabelPadCount      = 9
	v6LabelPadInterval   = 10
	v6LabelSmallLimit    = 11
	v6LabelBitMin        = 12
	v6LabelBitMax        = 13
	v6LabelPrefixMin     = 14
	v6LabelPrefixMax     = 15
	v6LabelMixMode       = 16
	v6LabelMixRounds     = 17
	v6LabelMixStride     = 18
	v6LabelMixOffsetBase = 19
	v6LabelMixBlock      = 20
	v6LabelChunkPolicy   = 21
	v6LabelChunkInitial  = 22
	v6LabelChunkFirstCap = 22
	v6LabelChunkMax      = 23
	v6LabelChunkStep     = 24
	v6LabelChunkJitter   = 25
	v6LabelChunkBucket   = 26
	v6LabelIdleReset     = 27
	v6LabelWritePolicy   = 28
	v6LabelWriteFirst    = 29
	v6LabelWriteBucket   = 30
	v6LabelWriteSeq      = 31
	v6LabelWriteJitter   = 32
	v6LabelRecordPrefix  = 33
	v6LabelPayloadPad    = 34
	v6LabelWriteTarget   = 35
	v6LabelWriteJitterV  = 36
	v6LabelWriteNext     = 37
	v6LabelChunkSize     = 38
	v6LabelChunkJitterV  = 39

	// domain separators for handshake and chunk profile values
	v6HandshakeDomain    = 0x7053
	v6MixHandshakeDomain = 0x51a7
	v6ChunkInitialDomain = 0xf17c

	// namespace seeds
	v6NSSeedProfile = 0xb46c2e7d9a1538f1
	v6NSSeedPrefix  = 0x5d9217c083e64ab9
	v6NSSeedMotif   = 0xa71f0c54d8396e2b
	v6NSSeedSalt    = 0x3e8a91b52740f6cd
	v6NSSeedMix     = 0xc9f4260b7d1e835a
	v6NSSeedChunk   = 0x62d0b5e19c4a783f
	v6NSSeedWrite   = 0x917b3c48e6a205d4

	// arithmetic constants of the profile PRFs
	v6DomainMul    = 0xd6e8feb86659fd93
	v6NamespaceAdd = 0xa0761d6478bd642f
	v6CoefB        = 0x589965cc75374cc3
	v6AddB         = 0x33a213ec50ffe2e9
	v6CoefA        = 0xe7037ed1a0b428db
	v6AddA         = 0x8f3907f7b2b80c35

	// salt shuffle/mask namespace xor
	v6SaltNSXor = 0xdaa66d2c7ddf743f

	v6MaxExtraPadding = 0x02da
)

// v6ProfileSeed is the BLAKE2b prefix mixed with the PSK to derive the profile secret.
var v6ProfileSeed = [...]byte{
	0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94,
	0x33, 0x18, 0xc0, 0x6e, 0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
}

// v6BitRotateTable maps low nibbles through bit rotations for padding generator 0.
var v6BitRotateTable = [...]byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
	0x03, 0x05, 0x09, 0x11, 0x21, 0x41, 0x81, 0x06, 0x0a, 0x12, 0x22, 0x42, 0x82, 0x0c, 0x18, 0x24,
	0x07, 0x0b, 0x13, 0x23, 0x43, 0x83, 0x0d, 0x19, 0x31, 0x61, 0xc1, 0x0e, 0x1c, 0x38, 0x70, 0xe0,
	0x0f, 0x17, 0x27, 0x47, 0x87, 0x1b, 0x33, 0x63, 0xc3, 0x1d, 0x39, 0x71, 0xe1, 0x3c, 0x78, 0xf0,
	0xf8, 0xf4, 0xec, 0xdc, 0xbc, 0x7c, 0xf2, 0xe6, 0xce, 0x9e, 0x3e, 0xf1, 0xe3, 0xc7, 0x8f, 0x1f,
	0xfc, 0xfa, 0xf6, 0xee, 0xde, 0xbe, 0x7e, 0xf9, 0xf5, 0xed, 0xdd, 0xbd, 0x7d, 0xf3, 0xe7, 0xdb,
	0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f, 0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f,
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func v6SplitMix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

func v6PRF32Fold(namespace uint64, label uint32, a uint64, b uint64) uint32 {
	x := namespace ^ (b*v6CoefB + v6AddB) ^ (uint64(label) * v6GoldenGamma) ^ (a*v6CoefA + v6AddA)
	y := v6SplitMix64(x)
	return uint32(y ^ (y >> 32))
}

func v6Pick(raw uint32, lo int, hi int) int {
	if hi < lo {
		panic("snell v6: invalid profile range")
	}
	return lo + int(uint64(raw)%uint64(hi-lo+1))
}

func v6PickU32(raw uint32, lo uint32, hi uint32) uint32 {
	if hi < lo {
		panic("snell v6: invalid profile range")
	}
	return lo + raw%(hi-lo+1)
}

type v6Namespaces struct {
	profile uint64
	prefix  uint64
	motif   uint64
	salt    uint64
	mix     uint64
	chunk   uint64
	write   uint64
}

func v6DeriveNamespace(secret []byte, label uint32, seedConst uint64) uint64 {
	s0 := binary.LittleEndian.Uint64(secret[0:])
	s1 := binary.LittleEndian.Uint64(secret[8:])
	s2 := binary.LittleEndian.Uint64(secret[16:])
	s3 := binary.LittleEndian.Uint64(secret[24:])
	mixed := uint64(label)*v6DomainMul ^
		(seedConst + v6NamespaceAdd) ^
		s0 ^
		(s1 + v6GoldenGamma) ^
		bits.RotateLeft64(s2, 17) ^
		bits.RotateLeft64(s3, -11)
	return v6SplitMix64(mixed)
}

func newV6Namespaces(secret []byte) v6Namespaces {
	return v6Namespaces{
		profile: v6DeriveNamespace(secret, v6LabelProfileID, v6NSSeedProfile),
		prefix:  v6DeriveNamespace(secret, v6LabelPadding, v6NSSeedPrefix),
		motif:   v6DeriveNamespace(secret, v6LabelMotif, v6NSSeedMotif),
		salt:    v6DeriveNamespace(secret, v6LabelSalt, v6NSSeedSalt),
		mix:     v6DeriveNamespace(secret, v6LabelMixMode, v6NSSeedMix),
		chunk:   v6DeriveNamespace(secret, v6LabelChunkPolicy, v6NSSeedChunk),
		write:   v6DeriveNamespace(secret, v6LabelWritePolicy, v6NSSeedWrite),
	}
}

func (n v6Namespaces) forLabel(label uint32) uint64 {
	switch label {
	case v6LabelPadding, v6LabelBitPercent, v6LabelPrefixMin, v6LabelPrefixMax, v6LabelRecordPrefix, v6LabelPayloadPad:
		return n.prefix
	case v6LabelMotif:
		return n.motif
	case v6LabelMixOffset, v6LabelMixMode, v6LabelMixRounds, v6LabelMixStride, v6LabelMixOffsetBase, v6LabelMixBlock:
		return n.mix
	case v6LabelChunkPolicy, v6LabelChunkInitial, v6LabelChunkMax, v6LabelChunkStep, v6LabelChunkJitter, v6LabelChunkBucket, v6LabelChunkSize, v6LabelChunkJitterV:
		return n.chunk
	case v6LabelWritePolicy, v6LabelWriteFirst, v6LabelWriteBucket, v6LabelWriteSeq, v6LabelWriteJitter, v6LabelWriteTarget, v6LabelWriteJitterV, v6LabelWriteNext:
		return n.write
	default:
		return n.profile
	}
}

func (n v6Namespaces) prf32(label uint32, a uint32, b uint32) uint32 {
	return v6PRF32Fold(n.forLabel(label), label, uint64(a), uint64(b))
}

func (n v6Namespaces) prfBytes(label uint32, a uint32, output []byte) {
	seed := n.forLabel(label) ^
		(uint64(a)*v6DomainMul + 0xb57de1f3f82cb33f) ^
		(uint64(label) * 0xa24baed4963ee407) ^
		(uint64(len(output))*0x165667b19e3779f9 + 0x0d4cd3e7b14a36d7)
	offset := 0
	for offset < len(output) {
		seed += v6GoldenGamma
		block := v6SplitMix64(seed)
		for shift := 0; shift < 64 && offset < len(output); shift += 8 {
			output[offset] = byte(block >> shift)
			offset++
		}
	}
}

func (n v6Namespaces) prfStatic(label uint32, domain uint32) uint32 {
	return v6PRF32Fold(n.forLabel(label), label, 0, uint64(domain))
}

type v6Profile struct {
	namespaces v6Namespaces

	generator       uint32
	padMin          int
	padMax          int
	padCount        uint32
	padInterval     uint32
	smallLimit      int
	bitMin          uint32
	bitMax          uint32
	prefixMinRecord int
	prefixMaxRecord int
	mixMode         uint32
	mixRounds       uint32
	mixStride       int
	mixOffsetBase   int
	mixBlock        int
	chunkPolicy     uint32
	chunkInitial    int
	firstRecordCap  int
	chunkMax        int
	chunkStep       int
	chunkJitter     int
	idleResetSec    int
	writePolicy     uint32
	writeFirst      uint32
	chunkBuckets    [8]int
	writeBuckets    [8]int
	writeSeq        [8]int
	writeJitter     int
	writeJitterPct  int
	g1              int
	g2              int
	g3              int
	g4              int
	g5              int
	g6              int

	saltBlockLen       int
	mixStrideHandshake int
	mixRoundsHandshake uint32
}

func v6ProfileSecret(psk []byte) [32]byte {
	input := make([]byte, len(v6ProfileSeed)+len(psk))
	copy(input, v6ProfileSeed[:])
	copy(input[len(v6ProfileSeed):], psk)
	return blake2b.Sum256(input)
}

func newV6Profile(psk []byte) *v6Profile {
	secret := v6ProfileSecret(psk)
	ns := newV6Namespaces(secret[:])

	padMin := v6Pick(ns.prfStatic(v6LabelPadMin, 0), 0x18, 0xa0)
	padMax := minInt(padMin+v6Pick(ns.prfStatic(v6LabelPadMax, 0), 0xa0, 0x3c0), v6MaxExtraPadding)

	prefixMinHS := v6Pick(ns.prfStatic(v6LabelPrefixMin, v6HandshakeDomain), 0x10, 0x60)
	prefixMaxHS := minInt(prefixMinHS+v6Pick(ns.prfStatic(v6LabelPrefixMax, v6HandshakeDomain), 0x10, 0xa0), 0x80)
	prefixMinHS = minInt(prefixMinHS, prefixMaxHS)
	saltPrefixLen := v6Pick(ns.prfStatic(v6LabelRecordPrefix, v6HandshakeDomain), prefixMinHS, prefixMaxHS)
	saltBlockLen := v6SaltSize + saltPrefixLen

	mixRoundsHS := v6PickU32(ns.prfStatic(v6LabelMixRounds, v6MixHandshakeDomain), 1, 4)
	mixStrideHS := v6Pick(ns.prfStatic(v6LabelMixStride, v6MixHandshakeDomain), 0x11, 0xfb)

	prefixMinRecord := v6Pick(ns.prfStatic(v6LabelPrefixMin, 0), 0x08, 0x50)
	prefixMaxRecord := minInt(prefixMinRecord+v6Pick(ns.prfStatic(v6LabelPrefixMax, 0), 0x10, 0xa0), 0x80)
	prefixMinRecord = minInt(prefixMinRecord, prefixMaxRecord)

	chunkInitial := maxInt(0x60, minInt(v6Pick(ns.prfStatic(v6LabelChunkInitial, 0), 0x200, 0x05b4), 0x05b4))
	firstRecordCap := maxInt(0x100, minInt(v6Pick(ns.prfStatic(v6LabelChunkFirstCap, v6ChunkInitialDomain), 0x100, 0x300), minInt(chunkInitial, 0x300)))
	chunkMax := maxInt(v6Pick(ns.prfStatic(v6LabelChunkMax, 0), 0x2000, 0x3fff), chunkInitial)

	profile := &v6Profile{
		namespaces:         ns,
		generator:          ns.prfStatic(v6LabelGenerator, 0) & 3,
		padMin:             padMin,
		padMax:             padMax,
		padCount:           v6PickU32(ns.prfStatic(v6LabelPadCount, 0), 2, 8),
		padInterval:        v6PickU32(ns.prfStatic(v6LabelPadInterval, 0), 2, 0x0b),
		smallLimit:         v6Pick(ns.prfStatic(v6LabelSmallLimit, 0), 0x60, 0x300),
		bitMin:             v6PickU32(ns.prfStatic(v6LabelBitMin, 0), 0x18, 0x29),
		bitMax:             v6PickU32(ns.prfStatic(v6LabelBitMax, 0), 0x3a, 0x4c),
		prefixMinRecord:    prefixMinRecord,
		prefixMaxRecord:    prefixMaxRecord,
		mixMode:            ns.prfStatic(v6LabelMixMode, 0) % 3,
		mixRounds:          v6PickU32(ns.prfStatic(v6LabelMixRounds, 0), 1, 3),
		mixStride:          v6Pick(ns.prfStatic(v6LabelMixStride, 0), 2, 13),
		mixOffsetBase:      v6Pick(ns.prfStatic(v6LabelMixOffsetBase, 0), 0, 15),
		mixBlock:           v6Pick(ns.prfStatic(v6LabelMixBlock, 0), 8, 0x40),
		chunkPolicy:        ns.prfStatic(v6LabelChunkPolicy, 0) % 3,
		chunkInitial:       chunkInitial,
		firstRecordCap:     firstRecordCap,
		chunkMax:           chunkMax,
		chunkStep:          minInt(v6Pick(ns.prfStatic(v6LabelChunkStep, 0), 0x400, 0x1000), 0x0b68),
		chunkJitter:        minInt(v6Pick(ns.prfStatic(v6LabelChunkJitter, 0), 0x10, 0xc0), 0x0b6),
		idleResetSec:       v6Pick(ns.prfStatic(v6LabelIdleReset, 0), 0x0c, 0x5a),
		writePolicy:        ns.prfStatic(v6LabelWritePolicy, 0) % 3,
		writeFirst:         v6PickU32(ns.prfStatic(v6LabelWriteFirst, 0), 4, 8),
		writeJitter:        v6Pick(ns.prfStatic(v6LabelWriteJitter, 0), 0x08, 0x60),
		writeJitterPct:     v6Pick(ns.prfStatic(v6LabelWritePolicy, 0x504c), 8, 0x30),
		g1:                 v6Pick(ns.prfStatic(v6LabelGenerator, 1), 0x18, 0x80),
		g2:                 v6Pick(ns.prfStatic(v6LabelGenerator, 2), 0x10, 0x60),
		g3:                 v6Pick(ns.prfStatic(v6LabelGenerator, 3), 0x10, 0x60),
		g4:                 v6Pick(ns.prfStatic(v6LabelGenerator, 4), 0x00, 0x09),
		g5:                 v6Pick(ns.prfStatic(v6LabelGenerator, 5), 0x01, 0x08),
		g6:                 v6Pick(ns.prfStatic(v6LabelGenerator, 6), 0x07, 0x17),
		saltBlockLen:       saltBlockLen,
		mixStrideHandshake: mixStrideHS,
		mixRoundsHandshake: mixRoundsHS,
	}

	for index := 0; index < 8; index++ {
		profile.chunkBuckets[index] = v6Pick(ns.prfStatic(v6LabelChunkBucket, uint32(index)), 0x1000, chunkMax)
		profile.writeBuckets[index] = v6Pick(ns.prfStatic(v6LabelWriteBucket, uint32(index)), 0x140, 0x05b4)
		profile.writeSeq[index] = v6Pick(ns.prfStatic(v6LabelWriteSeq, uint32(index)), 0x168, 0x05b4)
	}

	return profile
}

// recordPrefixLen returns the length of the unencrypted prefix in front of the
// header of the record with the given sequence number.
func (p *v6Profile) recordPrefixLen(seq uint32) int {
	return v6Pick(p.namespaces.prf32(v6LabelRecordPrefix, seq, 0), p.prefixMinRecord, p.prefixMaxRecord)
}

func (p *v6Profile) chunkPayloadLimit(seq uint32, chunkSize int) int {
	if chunkSize == 0 {
		chunkSize = p.chunkInitial
	}
	switch p.chunkPolicy {
	case 1:
		chunkSize = p.chunkBuckets[p.namespaces.prf32(v6LabelChunkSize, seq, uint32(chunkSize))%uint32(len(p.chunkBuckets))]
	case 2:
		rawJitter := p.namespaces.prf32(v6LabelChunkJitterV, seq, uint32(chunkSize))
		chunkSize += int(rawJitter%uint32(p.chunkJitter*2+1)) - p.chunkJitter
	}
	return maxInt(0x40, minInt(chunkSize, p.chunkMax))
}

func (p *v6Profile) nextChunkSize(chunkSize int) int {
	if chunkSize == 0 {
		return p.chunkInitial
	}
	return minInt(chunkSize+p.chunkStep, p.chunkMax)
}

// paddingLen decides how much padding the record with sequence number seq
// carries. totalLen is the salt block length when this is the first record.
func (p *v6Profile) paddingLen(seq uint32, payloadLen int, prefixLen int, saltPrefixLen int, totalLen int) int {
	paddingLen := 0
	if seq < p.padCount || (payloadLen > 0 && payloadLen <= p.smallLimit) || (p.padInterval > 0 && seq%p.padInterval == 0) {
		paddingLen = v6Pick(p.namespaces.prf32(v6LabelPayloadPad, seq, uint32(payloadLen)), p.padMin, p.padMax)
	}
	payloadTagLen := 0
	if payloadLen > 0 {
		payloadTagLen = v6TagSize
	}
	frameLen := totalLen + prefixLen + v6HeaderCipherSize + paddingLen + payloadLen + payloadTagLen
	targetLen := p.writeTarget(seq, frameLen)
	if targetLen > frameLen {
		paddingLen += minInt(targetLen-frameLen, v6MaxExtraPadding)
	}
	if totalLen > 0 {
		paddingLen = p.firstRecordPaddingLen(paddingLen, prefixLen, saltPrefixLen, payloadLen)
	}
	return minInt(paddingLen, 0xffff)
}

func (p *v6Profile) writeTarget(seq uint32, frameLen int) int {
	if frameLen > 0x05b3 {
		if frameLen <= 0xffff {
			return frameLen
		}
		return 0xffff
	}
	var targetLen int
	if seq < p.writeFirst {
		targetLen = p.writeSeq[seq]
	} else {
		targetLen = p.writeBuckets[p.namespaces.prf32(v6LabelWriteTarget, seq, uint32(frameLen))%uint32(len(p.writeBuckets))]
	}
	if p.writePolicy == 2 {
		rawJitter := p.namespaces.prf32(v6LabelWriteJitterV, seq, 0)
		jitter := int(rawJitter%uint32(p.writeJitter*2+1)) - p.writeJitter
		targetLen = maxInt(targetLen+jitter, 1)
	}
	spread := minInt(v6MaxExtraPadding, int(uint64(frameLen)*uint64(p.writeJitterPct)/100))
	if p.namespaces.prf32(v6LabelWriteTarget, seq, uint32(spread))&1 == 0 {
		if targetLen+spread <= 0xffff {
			targetLen += spread
		} else {
			targetLen = 0xffff
		}
	} else {
		halfSpread := spread >> 1
		if targetLen > halfSpread {
			targetLen -= halfSpread
		}
	}
	for targetLen >= 0 && frameLen > targetLen {
		nextLen := p.writeBuckets[p.namespaces.prf32(v6LabelWriteNext, seq, uint32(targetLen))%uint32(len(p.writeBuckets))]
		if nextLen <= targetLen {
			nextLen = targetLen + p.padMax
			if nextLen > 0xffff {
				return 0xffff
			}
		}
		targetLen = nextLen
	}
	return targetLen
}

func (p *v6Profile) firstRecordPaddingLen(paddingLen int, prefixLen int, saltPrefixLen int, payloadLen int) int {
	overheadLen := saltPrefixLen + prefixLen + paddingLen
	thresholdInput := payloadLen + 0x37
	if payloadLen == 0 {
		thresholdInput = payloadLen + 0x27
	}
	threshold := maxInt((thresholdInput*25+0x4a)/75, 0xc0)
	if overheadLen >= threshold {
		return paddingLen
	}
	targetPaddingLen := threshold - saltPrefixLen - prefixLen
	maxPaddingLen := p.padMax + v6MaxExtraPadding
	if maxPaddingLen <= targetPaddingLen {
		targetPaddingLen = maxPaddingLen
	}
	if targetPaddingLen > 0xfffe {
		return paddingLen
	}
	return targetPaddingLen
}

// fillPadding generates the deterministic padding bytes of a record.
func (p *v6Profile) fillPadding(seq uint32, output []byte) {
	if len(output) == 0 {
		return
	}
	p.namespaces.prfBytes(v6LabelPadding, seq, output)
	switch p.generator {
	case 0:
		bitCount := v6PickU32(p.namespaces.prf32(v6LabelBitPercent, seq, 0), p.bitMin, p.bitMax)
		rotate := 1
		scaled := int(bitCount) * 8
		if scaled > 0x31 {
			rotate = 7
			if scaled <= 0x02ed {
				rotate = (scaled + 0x32) / 100
			}
		}
		for index, value := range output {
			raw := byte(int(value) + index)
			tableRow := maxInt(rotate, 1)
			tableValue := v6BitRotateTable[tableRow*16+int((raw^value)&0x0f)]
			output[index] = bits.RotateLeft8(tableValue, int((raw^(value>>4))&7))
		}
	case 1:
		for index, value := range output {
			bucket := int(value) % (p.g1 + p.g2 + p.g3)
			switch {
			case bucket < p.g1:
				// the byte/index mix is truncated to a byte before being reduced into the printable range
				output[index] = byte(v6Pick(uint32(byte(int(value)+index)), 0x20, 0x7e))
			case bucket < p.g1+p.g2:
				output[index] = byte(v6Pick(uint32(byte(int(value)^index)), 0x80, 0xbf))
			default:
				output[index] = byte(v6Pick(uint32(byte(int(value)+index*7)), 0xc0, 0xff))
			}
		}
	case 2:
		for index, value := range output {
			low := (int(value&0x0f) + p.g4 + (index & 1)) % 10
			high := (int(value) + ((index & 3) << 4) + 0x30) & 0xf0
			output[index] = byte(high | low)
		}
	case 3:
		motif := make([]byte, 32)
		p.namespaces.prfBytes(v6LabelMotif, seq, motif)
		motifLen := p.g5 * 4
		if motifLen == 0 {
			motifLen = 4
		}
		period := maxInt(p.g6, 5)
		blockOffset := 0
		motifOffset := 0
		for index, value := range output {
			switch {
			case blockOffset < period-3:
				output[index] = byte((p.g5+3)*index) ^ motif[motifOffset%len(motif)]
			case blockOffset < period-1:
				output[index] = byte(0x30 | (int(value) % 10))
			}
			blockOffset++
			if blockOffset == period {
				blockOffset = 0
			}
			motifOffset++
			if motifOffset == motifLen {
				motifOffset = 0
			}
		}
	}
}

// --- salt block -------------------------------------------------------------

func v6SaltShufflePRF(nsSalt uint64, domain uint32, index uint32) uint32 {
	rdx := uint64(index)*v6CoefB + v6AddB
	rdi := nsSalt ^ v6SaltNSXor
	rsi := uint64(domain)*v6CoefA + v6AddA
	y := v6SplitMix64((rdx ^ rdi) ^ rsi)
	return uint32(y ^ (y >> 32))
}

func v6ShufflePerm(nsSalt uint64, rounds uint8, length int) []byte {
	out := make([]byte, length)
	for index := range out {
		out[index] = byte(index)
	}
	if length == 0 {
		return out
	}
	if rounds == 0 {
		rounds = 1
	}
	for round := uint32(0); round < uint32(rounds); round++ {
		domain := uint32(v6MixHandshakeDomain) + round
		for i := 0; i < length; i++ {
			span := uint64(length - i)
			raw := uint64(v6SaltShufflePRF(nsSalt, domain, uint32(i)))
			j := i + int(raw%span)
			out[i], out[j] = out[j], out[i]
		}
	}
	return out
}

func v6SaltMask(nsSalt uint64, mixStride uint8, index uint32) byte {
	prf := v6PRF32Fold(nsSalt, v6LabelMotif, uint64(v6MixHandshakeDomain), uint64(index))
	return byte(index)*mixStride ^ byte(prf)
}

// extractSalt recovers the 16-byte salt scattered inside the first block.
func (p *v6Profile) extractSalt(block []byte) [v6SaltSize]byte {
	perm := v6ShufflePerm(p.namespaces.salt, byte(p.mixRoundsHandshake), len(block))
	var out [v6SaltSize]byte
	for i := 0; i < v6SaltSize; i++ {
		out[i] = v6SaltMask(p.namespaces.salt, byte(p.mixStrideHandshake), uint32(i)) ^ block[perm[i]]
	}
	return out
}

// writeSaltBlock scatters the salt into block, which must already hold the
// shaped padding generated for the sentinel sequence 0xffffffff.
func (p *v6Profile) writeSaltBlock(salt []byte, block []byte) {
	perm := v6ShufflePerm(p.namespaces.salt, byte(p.mixRoundsHandshake), len(block))
	for i := 0; i < v6SaltSize; i++ {
		block[perm[i]] = v6SaltMask(p.namespaces.salt, byte(p.mixStrideHandshake), uint32(i)) ^ salt[i]
	}
}

// --- padding / ciphertext interleave -----------------------------------------

// mixPaddingPayload swaps bytes between the padding and the payload ciphertext.
// The operation is its own inverse, so the reader applies it before decrypting.
func (p *v6Profile) mixPaddingPayload(seq uint32, padding []byte, payloadCipher []byte) {
	n := minInt(len(padding), len(payloadCipher))
	if n == 0 {
		return
	}
	for round := uint32(0); round < p.mixRounds; round++ {
		switch p.mixMode {
		case 0:
			p.mixFixedStride(round, padding, payloadCipher, n)
		case 1:
			p.mixAlternatingBlock(round, padding, payloadCipher, n)
		case 2:
			p.mixPRFStride(seq, round, padding, payloadCipher, n)
		}
	}
}

func (p *v6Profile) mixFixedStride(round uint32, padding []byte, payloadCipher []byte, n int) {
	stride := maxInt(p.mixStride+int(round%3), 1)
	if stride == 1 {
		for i := 0; i < n; i++ {
			padding[i], payloadCipher[i] = payloadCipher[i], padding[i]
		}
		return
	}
	for off := p.mixOffsetBase % stride; off < n; off += stride {
		padding[off], payloadCipher[off] = payloadCipher[off], padding[off]
	}
}

func (p *v6Profile) mixAlternatingBlock(round uint32, padding []byte, payloadCipher []byte, n int) {
	block := p.mixBlock
	for off := int(round&1) * block; off+block <= n; off += block * 2 {
		for i := off; i < off+block; i++ {
			padding[i], payloadCipher[i] = payloadCipher[i], padding[i]
		}
	}
}

func (p *v6Profile) mixPRFStride(seq uint32, round uint32, padding []byte, payloadCipher []byte, n int) {
	stride := maxInt(p.mixStride+int(round%3), 1)
	off := int((uint64(p.namespaces.prf32(v6LabelMixOffset, seq, round)) + uint64(p.mixOffsetBase)) % uint64(stride))
	if stride == 1 {
		for i := 0; i < n; i++ {
			padding[i], payloadCipher[i] = payloadCipher[i], padding[i]
		}
		return
	}
	for ; off < n; off += stride {
		padding[off], payloadCipher[off] = payloadCipher[off], padding[off]
	}
}
