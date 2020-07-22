package protocol

// Base information for protocol
type Base struct {
	IV       []byte
	Key      []byte
	TCPMss   int
	Overhead int
	Param    string
}
