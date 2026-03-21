package pool

func Get(size int) []byte {
	return DefaultAllocator.Get(size)
}

func Put(buf []byte) error {
	return DefaultAllocator.Put(buf)
}
