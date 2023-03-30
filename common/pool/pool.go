package pool

func Get(size int) []byte {
	return defaultAllocator.Get(size)
}

func Put(buf []byte) error {
	return defaultAllocator.Put(buf)
}
