package obfs

import (
	"crypto/sha256"
	"math/rand"
	"sync"
	"time"
)

// [salt][obfuscated payload]

const saltLen = 16

type XPlusObfuscator struct {
	Key     []byte
	RandSrc *rand.Rand

	lk sync.Mutex
}

func NewXPlusObfuscator(key []byte) *XPlusObfuscator {
	return &XPlusObfuscator{
		Key:     key,
		RandSrc: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (x *XPlusObfuscator) Deobfuscate(in []byte, out []byte) int {
	pLen := len(in) - saltLen
	if pLen <= 0 || len(out) < pLen {
		// Invalid
		return 0
	}
	key := sha256.Sum256(append(x.Key, in[:saltLen]...))
	// Deobfuscate the payload
	for i, c := range in[saltLen:] {
		out[i] = c ^ key[i%sha256.Size]
	}
	return pLen
}

func (x *XPlusObfuscator) Obfuscate(in []byte, out []byte) int {
	x.lk.Lock()
	_, _ = x.RandSrc.Read(out[:saltLen]) // salt
	x.lk.Unlock()
	// Obfuscate the payload
	key := sha256.Sum256(append(x.Key, out[:saltLen]...))
	for i, c := range in {
		out[i+saltLen] = c ^ key[i%sha256.Size]
	}
	return len(in) + saltLen
}
