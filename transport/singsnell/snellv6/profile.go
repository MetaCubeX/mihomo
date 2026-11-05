package snellv6

import (
	"encoding/binary"
	"github.com/metacubex/sing/common"
	"math/bits"

	snell "github.com/metacubex/mihomo/transport/singsnell"

	"golang.org/x/crypto/blake2b"
)

// Surge 6.7.0 (11520): FUN_1000130ac: derives v6 profile values with this SplitMix64 gamma.
const goldenGamma = 0x9e3779b97f4a7c15

const saltLen = 16

const (
	// Surge 6.7.0 (11520): FUN_1000130ac: uses these PRF labels for v6 profile derivation.
	labelPadding       = 0
	labelBitPercent    = 1
	labelMotif         = 2
	labelMixOffset     = 3
	labelSalt          = 3
	labelProfileID     = 5
	labelGenerator     = 6
	labelPadMin        = 7
	labelPadMax        = 8
	labelPadCount      = 9
	labelPadInterval   = 10
	labelSmallLimit    = 11
	labelBitMin        = 12
	labelBitMax        = 13
	labelPrefixMin     = 14
	labelPrefixMax     = 15
	labelMixMode       = 16
	labelMixRounds     = 17
	labelMixStride     = 18
	labelMixOffsetBase = 19
	labelMixBlock      = 20
	labelChunkPolicy   = 21
	labelChunkInitial  = 22
	labelChunkFirstCap = 22
	labelChunkMax      = 23
	labelChunkStep     = 24
	labelChunkJitter   = 25
	labelChunkBucket   = 26
	labelIdleReset     = 27
	labelWritePolicy   = 28
	labelWriteFirst    = 29
	labelWriteBucket   = 30
	labelWriteSeq      = 31
	labelWriteJitter   = 32
	labelRecordPrefix  = 33
	labelPayloadPad    = 34
	labelWriteTarget   = 35
	labelWriteJitterV  = 36
	labelWriteNext     = 37
	labelChunkSize     = 38
	labelChunkJitterV  = 39
)

const (
	// Surge 6.7.0 (11520): FUN_1000130ac: uses these domain separators for handshake and chunk profile values.
	handshakeDomain    = 0x7053
	mixHandshakeDomain = 0x51a7
	chunkInitialDomain = 0xf17c
)

const (
	// Surge 6.7.0 (11520): FUN_1000130ac: uses these namespace seeds for v6 profile derivation.
	nsSeedProfile = 0xb46c2e7d9a1538f1
	nsSeedPrefix  = 0x5d9217c083e64ab9
	nsSeedMotif   = 0xa71f0c54d8396e2b
	nsSeedSalt    = 0x3e8a91b52740f6cd
	nsSeedMix     = 0xc9f4260b7d1e835a
	nsSeedChunk   = 0x62d0b5e19c4a783f
	nsSeedWrite   = 0x917b3c48e6a205d4
)

const (
	// Surge 6.7.0 (11520): FUN_100014910/FUN_1000149c4: uses these arithmetic constants for v6 profile PRFs.
	domainMul       = 0xd6e8feb86659fd93
	namespaceAdd    = 0xa0761d6478bd642f
	coefB           = 0x589965cc75374cc3
	addB            = 0x33a213ec50ffe2e9
	coefA           = 0xe7037ed1a0b428db
	addA            = 0x8f3907f7b2b80c35
	maxExtraPadding = 0x02da
)

// Surge 6.7.0 (11520): FUN_1000130ac: profileSeed is the BLAKE2b prefix mixed with the PSK to derive the profile secret.
var profileSeed = [...]byte{
	0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94,
	0x33, 0x18, 0xc0, 0x6e, 0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
}

// Surge 6.7.0 (11520): FUN_100014f98: generator 0 maps low nibbles through this bit-rotation table.
var bitRotateTable = [...]byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
	0x03, 0x05, 0x09, 0x11, 0x21, 0x41, 0x81, 0x06, 0x0a, 0x12, 0x22, 0x42, 0x82, 0x0c, 0x18, 0x24,
	0x07, 0x0b, 0x13, 0x23, 0x43, 0x83, 0x0d, 0x19, 0x31, 0x61, 0xc1, 0x0e, 0x1c, 0x38, 0x70, 0xe0,
	0x0f, 0x17, 0x27, 0x47, 0x87, 0x1b, 0x33, 0x63, 0xc3, 0x1d, 0x39, 0x71, 0xe1, 0x3c, 0x78, 0xf0,
	0xf8, 0xf4, 0xec, 0xdc, 0xbc, 0x7c, 0xf2, 0xe6, 0xce, 0x9e, 0x3e, 0xf1, 0xe3, 0xc7, 0x8f, 0x1f,
	0xfc, 0xfa, 0xf6, 0xee, 0xde, 0xbe, 0x7e, 0xf9, 0xf5, 0xed, 0xdd, 0xbd, 0x7d, 0xf3, 0xe7, 0xdb,
	0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f, 0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f,
}

func splitmix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

func prf32Fold(namespace uint64, label uint32, a uint64, b uint64) uint32 {
	x := namespace ^ (b*coefB + addB) ^ (uint64(label) * goldenGamma) ^ (a*coefA + addA)
	y := splitmix64(x)
	return uint32(y ^ (y >> 32))
}

func pick(raw uint32, lo int, hi int) int {
	if hi < lo {
		panic("snell: invalid profile range")
	}
	return lo + int(uint64(raw)%uint64(hi-lo+1))
}

func pickU32(raw uint32, lo uint32, hi uint32) uint32 {
	if hi < lo {
		panic("snell: invalid profile range")
	}
	return lo + raw%(hi-lo+1)
}

type namespaces struct {
	profile uint64
	prefix  uint64
	motif   uint64
	salt    uint64
	mix     uint64
	chunk   uint64
	write   uint64
}

func deriveNamespace(secret []byte, label uint32, seedConst uint64) uint64 {
	s0 := binary.LittleEndian.Uint64(secret[0:])
	s1 := binary.LittleEndian.Uint64(secret[8:])
	s2 := binary.LittleEndian.Uint64(secret[16:])
	s3 := binary.LittleEndian.Uint64(secret[24:])
	mixed := uint64(label)*domainMul ^
		(seedConst + namespaceAdd) ^
		s0 ^
		(s1 + goldenGamma) ^
		bits.RotateLeft64(s2, 17) ^
		bits.RotateLeft64(s3, -11)
	return splitmix64(mixed)
}

func newNamespaces(secret []byte) namespaces {
	return namespaces{
		profile: deriveNamespace(secret, labelProfileID, nsSeedProfile),
		prefix:  deriveNamespace(secret, labelPadding, nsSeedPrefix),
		motif:   deriveNamespace(secret, labelMotif, nsSeedMotif),
		salt:    deriveNamespace(secret, labelSalt, nsSeedSalt),
		mix:     deriveNamespace(secret, labelMixMode, nsSeedMix),
		chunk:   deriveNamespace(secret, labelChunkPolicy, nsSeedChunk),
		write:   deriveNamespace(secret, labelWritePolicy, nsSeedWrite),
	}
}

func (n namespaces) forLabel(label uint32) uint64 {
	switch label {
	case labelPadding, labelBitPercent, labelPrefixMin, labelPrefixMax, labelRecordPrefix, labelPayloadPad:
		return n.prefix
	case labelMotif:
		return n.motif
	case labelMixOffset, labelMixMode, labelMixRounds, labelMixStride, labelMixOffsetBase, labelMixBlock:
		return n.mix
	case labelChunkPolicy, labelChunkInitial, labelChunkMax, labelChunkStep, labelChunkJitter, labelChunkBucket, labelChunkSize, labelChunkJitterV:
		return n.chunk
	case labelWritePolicy, labelWriteFirst, labelWriteBucket, labelWriteSeq, labelWriteJitter, labelWriteTarget, labelWriteJitterV, labelWriteNext:
		return n.write
	default:
		return n.profile
	}
}

func (n namespaces) prf32(label uint32, a uint32, b uint32) uint32 {
	return prf32Fold(n.forLabel(label), label, uint64(a), uint64(b))
}

func (n namespaces) prfBytes(label uint32, a uint32, output []byte) {
	seed := n.forLabel(label) ^
		(uint64(a)*domainMul + 0xb57de1f3f82cb33f) ^
		(uint64(label) * 0xa24baed4963ee407) ^
		(uint64(len(output))*0x165667b19e3779f9 + 0x0d4cd3e7b14a36d7)
	offset := 0
	for offset < len(output) {
		seed += goldenGamma
		block := splitmix64(seed)
		for shift := 0; shift < 64 && offset < len(output); shift += 8 {
			output[offset] = byte(block >> shift)
			offset++
		}
	}
}

func (n namespaces) prfStatic(label uint32, domain uint32) uint32 {
	return prf32Fold(n.forLabel(label), label, 0, uint64(domain))
}

type Profile struct {
	namespaces namespaces

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

	recordPrefixMax int
	padMaxHeadroom  int
}

func profileSecret(psk []byte) [32]byte {
	input := make([]byte, len(profileSeed)+len(psk))
	copy(input, profileSeed[:])
	copy(input[len(profileSeed):], psk)
	return blake2b.Sum256(input)
}

func NewProfile(psk []byte) *Profile {
	secret := profileSecret(psk)
	ns := newNamespaces(secret[:])

	padMin := pick(ns.prfStatic(labelPadMin, 0), 0x18, 0xa0)
	padMax := common.Min(padMin+pick(ns.prfStatic(labelPadMax, 0), 0xa0, 0x3c0), maxExtraPadding)

	prefixMinHS := pick(ns.prfStatic(labelPrefixMin, handshakeDomain), 0x10, 0x60)
	prefixMaxHS := common.Min(prefixMinHS+pick(ns.prfStatic(labelPrefixMax, handshakeDomain), 0x10, 0xa0), 0x80)
	prefixMinHS = common.Min(prefixMinHS, prefixMaxHS)
	saltPrefixLen := pick(ns.prfStatic(labelRecordPrefix, handshakeDomain), prefixMinHS, prefixMaxHS)
	saltBlockLen := saltLen + saltPrefixLen

	mixRoundsHS := pickU32(ns.prfStatic(labelMixRounds, mixHandshakeDomain), 1, 4)
	mixStrideHS := pick(ns.prfStatic(labelMixStride, mixHandshakeDomain), 0x11, 0xfb)

	prefixMinRecord := pick(ns.prfStatic(labelPrefixMin, 0), 0x08, 0x50)
	prefixMaxRecord := common.Min(prefixMinRecord+pick(ns.prfStatic(labelPrefixMax, 0), 0x10, 0xa0), 0x80)
	prefixMinRecord = common.Min(prefixMinRecord, prefixMaxRecord)

	chunkInitial := common.Max(0x60, common.Min(pick(ns.prfStatic(labelChunkInitial, 0), 0x200, 0x05b4), 0x05b4))
	firstRecordCap := common.Max(0x100, common.Min(pick(ns.prfStatic(labelChunkFirstCap, chunkInitialDomain), 0x100, 0x300), common.Min(chunkInitial, 0x300)))
	chunkMax := common.Max(pick(ns.prfStatic(labelChunkMax, 0), 0x2000, 0x3fff), chunkInitial)

	profile := &Profile{
		namespaces:         ns,
		generator:          ns.prfStatic(labelGenerator, 0) & 3,
		padMin:             padMin,
		padMax:             padMax,
		padCount:           pickU32(ns.prfStatic(labelPadCount, 0), 2, 8),
		padInterval:        pickU32(ns.prfStatic(labelPadInterval, 0), 2, 0x0b),
		smallLimit:         pick(ns.prfStatic(labelSmallLimit, 0), 0x60, 0x300),
		bitMin:             pickU32(ns.prfStatic(labelBitMin, 0), 0x18, 0x29),
		bitMax:             pickU32(ns.prfStatic(labelBitMax, 0), 0x3a, 0x4c),
		prefixMinRecord:    prefixMinRecord,
		prefixMaxRecord:    prefixMaxRecord,
		mixMode:            ns.prfStatic(labelMixMode, 0) % 3,
		mixRounds:          pickU32(ns.prfStatic(labelMixRounds, 0), 1, 3),
		mixStride:          pick(ns.prfStatic(labelMixStride, 0), 2, 13),
		mixOffsetBase:      pick(ns.prfStatic(labelMixOffsetBase, 0), 0, 15),
		mixBlock:           pick(ns.prfStatic(labelMixBlock, 0), 8, 0x40),
		chunkPolicy:        ns.prfStatic(labelChunkPolicy, 0) % 3,
		chunkInitial:       chunkInitial,
		firstRecordCap:     firstRecordCap,
		chunkMax:           chunkMax,
		chunkStep:          common.Min(pick(ns.prfStatic(labelChunkStep, 0), 0x400, 0x1000), 0x0b68),
		chunkJitter:        common.Min(pick(ns.prfStatic(labelChunkJitter, 0), 0x10, 0xc0), 0x0b6),
		idleResetSec:       pick(ns.prfStatic(labelIdleReset, 0), 0x0c, 0x5a),
		writePolicy:        ns.prfStatic(labelWritePolicy, 0) % 3,
		writeFirst:         pickU32(ns.prfStatic(labelWriteFirst, 0), 4, 8),
		writeJitter:        pick(ns.prfStatic(labelWriteJitter, 0), 0x08, 0x60),
		writeJitterPct:     pick(ns.prfStatic(labelWritePolicy, 0x504c), 8, 0x30),
		g1:                 pick(ns.prfStatic(labelGenerator, 1), 0x18, 0x80),
		g2:                 pick(ns.prfStatic(labelGenerator, 2), 0x10, 0x60),
		g3:                 pick(ns.prfStatic(labelGenerator, 3), 0x10, 0x60),
		g4:                 pick(ns.prfStatic(labelGenerator, 4), 0x00, 0x09),
		g5:                 pick(ns.prfStatic(labelGenerator, 5), 0x01, 0x08),
		g6:                 pick(ns.prfStatic(labelGenerator, 6), 0x07, 0x17),
		saltBlockLen:       saltBlockLen,
		mixStrideHandshake: mixStrideHS,
		mixRoundsHandshake: mixRoundsHS,
		recordPrefixMax:    prefixMaxRecord,
		padMaxHeadroom:     padMax + maxExtraPadding,
	}

	for index := 0; index < 8; index++ {
		profile.chunkBuckets[index] = pick(ns.prfStatic(labelChunkBucket, uint32(index)), 0x1000, chunkMax)
		profile.writeBuckets[index] = pick(ns.prfStatic(labelWriteBucket, uint32(index)), 0x140, 0x05b4)
		profile.writeSeq[index] = pick(ns.prfStatic(labelWriteSeq, uint32(index)), 0x168, 0x05b4)
	}

	return profile
}

func (p *Profile) recordPrefixLen(seq uint32) int {
	return pick(p.namespaces.prf32(labelRecordPrefix, seq, 0), p.prefixMinRecord, p.prefixMaxRecord)
}

func (p *Profile) chunkPayloadLimit(seq uint32, chunkSize int) int {
	if chunkSize == 0 {
		chunkSize = p.chunkInitial
	}
	switch p.chunkPolicy {
	case 1:
		chunkSize = p.chunkBuckets[p.namespaces.prf32(labelChunkSize, seq, uint32(chunkSize))%uint32(len(p.chunkBuckets))]
	case 2:
		rawJitter := p.namespaces.prf32(labelChunkJitterV, seq, uint32(chunkSize))
		chunkSize += int(rawJitter%uint32(p.chunkJitter*2+1)) - p.chunkJitter
	}
	return common.Max(0x40, common.Min(chunkSize, p.chunkMax))
}

func (p *Profile) nextChunkSize(chunkSize int) int {
	if chunkSize == 0 {
		return p.chunkInitial
	}
	return common.Min(chunkSize+p.chunkStep, p.chunkMax)
}

func (p *Profile) paddingLen(seq uint32, payloadLen int, prefixLen int, saltPrefixLen int, totalLen int) int {
	paddingLen := 0
	if seq < p.padCount || (payloadLen > 0 && payloadLen <= p.smallLimit) || (p.padInterval > 0 && seq%p.padInterval == 0) {
		paddingLen = pick(p.namespaces.prf32(labelPayloadPad, seq, uint32(payloadLen)), p.padMin, p.padMax)
	}
	payloadTagLen := 0
	if payloadLen > 0 {
		payloadTagLen = snell.AEADTagLen
	}
	frameLen := totalLen + prefixLen + snell.HeaderCipherLen + paddingLen + payloadLen + payloadTagLen
	targetLen := p.writeTarget(seq, frameLen)
	if targetLen > frameLen {
		paddingLen += common.Min(targetLen-frameLen, maxExtraPadding)
	}
	if totalLen > 0 {
		paddingLen = p.firstRecordPaddingLen(paddingLen, prefixLen, saltPrefixLen, payloadLen)
	}
	return common.Min(paddingLen, 0xffff)
}

func (p *Profile) writeTarget(seq uint32, frameLen int) int {
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
		targetLen = p.writeBuckets[p.namespaces.prf32(labelWriteTarget, seq, uint32(frameLen))%uint32(len(p.writeBuckets))]
	}
	if p.writePolicy == 2 {
		rawJitter := p.namespaces.prf32(labelWriteJitterV, seq, 0)
		jitter := int(rawJitter%uint32(p.writeJitter*2+1)) - p.writeJitter
		targetLen = common.Max(targetLen+jitter, 1)
	}
	spread := common.Min(maxExtraPadding, int(uint64(frameLen)*uint64(p.writeJitterPct)/100))
	if p.namespaces.prf32(labelWriteTarget, seq, uint32(spread))&1 == 0 {
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
		nextLen := p.writeBuckets[p.namespaces.prf32(labelWriteNext, seq, uint32(targetLen))%uint32(len(p.writeBuckets))]
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

func (p *Profile) firstRecordPaddingLen(paddingLen int, prefixLen int, saltPrefixLen int, payloadLen int) int {
	overheadLen := saltPrefixLen + prefixLen + paddingLen
	thresholdInput := payloadLen + 0x37
	if payloadLen == 0 {
		thresholdInput = payloadLen + 0x27
	}
	threshold := common.Max((thresholdInput*25+0x4a)/75, 0xc0)
	if overheadLen >= threshold {
		return paddingLen
	}
	targetPaddingLen := threshold - saltPrefixLen - prefixLen
	maxPaddingLen := p.padMax + maxExtraPadding
	if maxPaddingLen <= targetPaddingLen {
		targetPaddingLen = maxPaddingLen
	}
	if targetPaddingLen > 0xfffe {
		return paddingLen
	}
	return targetPaddingLen
}

func (p *Profile) fillPadding(seq uint32, output []byte) {
	if len(output) == 0 {
		return
	}
	p.namespaces.prfBytes(labelPadding, seq, output)
	switch p.generator {
	case 0:
		bitCount := pickU32(p.namespaces.prf32(labelBitPercent, seq, 0), p.bitMin, p.bitMax)
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
			tableRow := common.Max(rotate, 1)
			tableValue := bitRotateTable[tableRow*16+int((raw^value)&0x0f)]
			output[index] = bits.RotateLeft8(tableValue, int((raw^(value>>4))&7))
		}
	case 1:
		for index, value := range output {
			bucket := int(value) % (p.g1 + p.g2 + p.g3)
			switch {
			case bucket < p.g1:
				// Surge 6.7.0 (11520): FUN_100014f98: truncates the byte/index mix before
				// reducing it into the printable range.
				output[index] = byte(pick(uint32(byte(int(value)+index)), 0x20, 0x7e))
			case bucket < p.g1+p.g2:
				output[index] = byte(pick(uint32(byte(int(value)^index)), 0x80, 0xbf))
			default:
				output[index] = byte(pick(uint32(byte(int(value)+index*7)), 0xc0, 0xff))
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
		p.namespaces.prfBytes(labelMotif, seq, motif)
		motifLen := p.g5 * 4
		if motifLen == 0 {
			motifLen = 4
		}
		period := common.Max(p.g6, 5)
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
