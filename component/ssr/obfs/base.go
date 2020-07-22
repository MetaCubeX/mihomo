package obfs

// Base information for obfs
type Base struct {
	IVSize  int
	Key     []byte
	HeadLen int
	Host    string
	Port    int
	Param   string
}
