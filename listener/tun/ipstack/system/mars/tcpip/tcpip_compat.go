package tcpip

func SumCompat(b []byte) (sum uint32) {
	n := len(b)
	if n&1 != 0 {
		n--
		sum += uint32(b[n]) << 8
	}

	for i := 0; i < n; i += 2 {
		sum += (uint32(b[i]) << 8) | uint32(b[i+1])
	}
	return
}
