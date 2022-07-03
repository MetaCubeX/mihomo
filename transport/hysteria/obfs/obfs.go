package obfs

type Obfuscator interface {
	Deobfuscate(in []byte, out []byte) int
	Obfuscate(in []byte, out []byte) int
}
