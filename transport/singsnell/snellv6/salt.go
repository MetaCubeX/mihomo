package snellv6

// Surge 6.7.0 (11520): FUN_100015274/FUN_1000140bc: shuffles and masks v6 default-mode salts with this namespace xor.
const saltNSXor = 0xdaa66d2c7ddf743f

func saltShufflePRF(nsSalt uint64, domain uint32, index uint32) uint32 {
	rdx := uint64(index)*coefB + addB
	rdi := nsSalt ^ saltNSXor
	rsi := uint64(domain)*coefA + addA
	y := splitmix64((rdx ^ rdi) ^ rsi)
	return uint32(y ^ (y >> 32))
}

func shufflePerm(nsSalt uint64, rounds uint8, length int) []byte {
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
		domain := uint32(mixHandshakeDomain) + round
		for i := 0; i < length; i++ {
			span := uint64(length - i)
			raw := uint64(saltShufflePRF(nsSalt, domain, uint32(i)))
			j := i + int(raw%span)
			out[i], out[j] = out[j], out[i]
		}
	}
	return out
}

func saltMask(nsSalt uint64, mixStride uint8, index uint32) byte {
	prf := prf32Fold(nsSalt, labelMotif, uint64(mixHandshakeDomain), uint64(index))
	return byte(index)*mixStride ^ byte(prf)
}

func (p *Profile) extractSalt(block []byte) [saltLen]byte {
	perm := shufflePerm(p.namespaces.salt, byte(p.mixRoundsHandshake), len(block))
	var out [saltLen]byte
	for i := 0; i < saltLen; i++ {
		out[i] = saltMask(p.namespaces.salt, byte(p.mixStrideHandshake), uint32(i)) ^ block[perm[i]]
	}
	return out
}

func (p *Profile) writeSaltBlock(salt []byte, block []byte) {
	perm := shufflePerm(p.namespaces.salt, byte(p.mixRoundsHandshake), len(block))
	for i := 0; i < saltLen; i++ {
		block[perm[i]] = saltMask(p.namespaces.salt, byte(p.mixStrideHandshake), uint32(i)) ^ salt[i]
	}
}
