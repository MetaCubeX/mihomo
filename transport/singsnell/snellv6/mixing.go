package snellv6

import "github.com/metacubex/sing/common"

func (p *Profile) mixPaddingPayload(seq uint32, padding []byte, payloadCipher []byte) {
	n := common.Min(len(padding), len(payloadCipher))
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

func (p *Profile) mixFixedStride(round uint32, padding []byte, payloadCipher []byte, n int) {
	stride := common.Max(p.mixStride+int(round%3), 1)
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

func (p *Profile) mixAlternatingBlock(round uint32, padding []byte, payloadCipher []byte, n int) {
	block := p.mixBlock
	for off := int(round&1) * block; off+block <= n; off += block * 2 {
		for i := off; i < off+block; i++ {
			padding[i], payloadCipher[i] = payloadCipher[i], padding[i]
		}
	}
}

func (p *Profile) mixPRFStride(seq uint32, round uint32, padding []byte, payloadCipher []byte, n int) {
	stride := common.Max(p.mixStride+int(round%3), 1)
	off := int((uint64(p.namespaces.prf32(labelMixOffset, seq, round)) + uint64(p.mixOffsetBase)) % uint64(stride))
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
