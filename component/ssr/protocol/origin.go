package protocol

type origin struct{ *Base }

func init() {
	register("origin", newOrigin)
}

func newOrigin(b *Base) Protocol {
	return &origin{}
}

func (o *origin) initForConn(iv []byte) Protocol { return &origin{} }

func (o *origin) GetProtocolOverhead() int {
	return 0
}

func (o *origin) SetOverhead(overhead int) {
}

func (o *origin) Decode(b []byte) ([]byte, int, error) {
	return b, len(b), nil
}

func (o *origin) Encode(b []byte) ([]byte, error) {
	return b, nil
}

func (o *origin) DecodePacket(b []byte) ([]byte, int, error) {
	return b, len(b), nil
}

func (o *origin) EncodePacket(b []byte) ([]byte, error) {
	return b, nil
}
