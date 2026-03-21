package maphash

import "hash/maphash"

type Seed = maphash.Seed

func MakeSeed() Seed {
	return maphash.MakeSeed()
}

type Hash = maphash.Hash

func Bytes(seed Seed, b []byte) uint64 {
	return maphash.Bytes(seed, b)
}

func String(seed Seed, s string) uint64 {
	return maphash.String(seed, s)
}
