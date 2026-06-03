package mkcp

// xorfwd performs XOR forwards in words, x[i] ^= x[i-4], i from 0 to len.
func xorfwd(x []byte) {
	for i := 4; i < len(x); i++ {
		x[i] ^= x[i-4]
	}
}

// xorbkd performs XOR backwards in words, x[i] ^= x[i-4], i from len to 0.
func xorbkd(x []byte) {
	for i := len(x) - 1; i >= 4; i-- {
		x[i] ^= x[i-4]
	}
}
