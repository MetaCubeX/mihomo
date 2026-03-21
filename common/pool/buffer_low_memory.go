//go:build with_low_memory

package pool

const (
	// RelayBufferSize using for tcp
	// io.Copy default buffer size is 32 KiB
	RelayBufferSize = 16 * 1024

	// UDPBufferSize using for udp
	// Most UDPs are smaller than the MTU, and the TUN's MTU
	// set to 9000, so the UDP Buffer size set to 16Kib
	UDPBufferSize = 8 * 1024
)
