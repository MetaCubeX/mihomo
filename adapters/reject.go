package adapters

import (
	"io"

	C "github.com/Dreamacro/clash/constant"
)

// RejectAdapter is a reject connected adapter
type RejectAdapter struct {
}

// Writer is used to output network traffic
func (r *RejectAdapter) Writer() io.Writer {
	return &NopRW{}
}

// Reader is used to input network traffic
func (r *RejectAdapter) Reader() io.Reader {
	return &NopRW{}
}

// Close is used to close connection
func (r *RejectAdapter) Close() {
}

type Reject struct {
}

func (r *Reject) Generator(addr *C.Addr) (adapter C.ProxyAdapter, err error) {
	return &RejectAdapter{}, nil
}

func NewReject() *Reject {
	return &Reject{}
}

type NopRW struct{}

func (rw *NopRW) Read(b []byte) (int, error) {
	return len(b), nil
}

func (rw *NopRW) Write(b []byte) (int, error) {
	return 0, io.EOF
}
