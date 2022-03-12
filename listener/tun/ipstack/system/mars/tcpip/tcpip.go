package tcpip

var zeroChecksum = [2]byte{0x00, 0x00}

var SumFnc = SumCompat

func Sum(b []byte) uint32 {
	return SumFnc(b)
}

// Checksum for Internet Protocol family headers
func Checksum(sum uint32, b []byte) (answer [2]byte) {
	sum += Sum(b)
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	sum = ^sum
	answer[0] = byte(sum >> 8)
	answer[1] = byte(sum)
	return
}

func SetIPv4(packet []byte) {
	packet[0] = (packet[0] & 0x0f) | (4 << 4)
}
