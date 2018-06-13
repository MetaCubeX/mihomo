package adapters

import (
	"io"
	"net"

	C "github.com/Dreamacro/clash/constant"
)

// RejectAdapter is a reject connected adapter
type RejectAdapter struct {
}

// ReadWriter is used to handle network traffic
func (r *RejectAdapter) ReadWriter() io.ReadWriter {
	return &NopRW{}
}

// Close is used to close connection
func (r *RejectAdapter) Close() {}

// Close is used to close connection
func (r *RejectAdapter) Conn() net.Conn {
	return nil
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
