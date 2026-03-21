package obfs

type DummyObfuscator struct{}

func NewDummyObfuscator() *DummyObfuscator {
	return &DummyObfuscator{}
}

func (x *DummyObfuscator) Deobfuscate(in []byte, out []byte) int {
	if len(out) < len(in) {
		return 0
	}
	return copy(out, in)
}

func (x *DummyObfuscator) Obfuscate(in []byte, out []byte) int {
	return copy(out, in)
}
