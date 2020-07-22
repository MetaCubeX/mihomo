package obfs

type plain struct{}

func init() {
	register("plain", newPlain)
}

func newPlain(b *Base) Obfs {
	return &plain{}
}

func (p *plain) initForConn() Obfs { return &plain{} }

func (p *plain) GetObfsOverhead() int {
	return 0
}

func (p *plain) Encode(b []byte) ([]byte, error) {
	return b, nil
}

func (p *plain) Decode(b []byte) ([]byte, bool, error) {
	return b, false, nil
}
