package deadline

import (
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

type pipe struct {
	wrMu sync.Mutex // Serialize Write operations

	// Used by local Read to interact with remote Write.
	// Successful receive on rdRx is always followed by send on rdTx.
	rdRx <-chan []byte
	rdTx chan<- int

	// Used by local Write to interact with remote Read.
	// Successful send on wrTx is always followed by receive on wrRx.
	wrTx chan<- []byte
	wrRx <-chan int

	once       sync.Once // Protects closing localDone
	localDone  chan struct{}
	remoteDone <-chan struct{}

	readDeadline  pipeDeadline
	writeDeadline pipeDeadline

	readWaitOptions N.ReadWaitOptions
}

// Pipe creates a synchronous, in-memory, full duplex
// network connection; both ends implement the Conn interface.
// Reads on one end are matched with writes on the other,
// copying data directly between the two; there is no internal
// buffering.
func Pipe() (net.Conn, net.Conn) {
	cb1 := make(chan []byte)
	cb2 := make(chan []byte)
	cn1 := make(chan int)
	cn2 := make(chan int)
	done1 := make(chan struct{})
	done2 := make(chan struct{})

	p1 := &pipe{
		rdRx: cb1, rdTx: cn1,
		wrTx: cb2, wrRx: cn2,
		localDone: done1, remoteDone: done2,
		readDeadline:  makePipeDeadline(),
		writeDeadline: makePipeDeadline(),
	}
	p2 := &pipe{
		rdRx: cb2, rdTx: cn2,
		wrTx: cb1, wrRx: cn1,
		localDone: done2, remoteDone: done1,
		readDeadline:  makePipeDeadline(),
		writeDeadline: makePipeDeadline(),
	}
	return p1, p2
}

func (*pipe) LocalAddr() net.Addr  { return pipeAddr{} }
func (*pipe) RemoteAddr() net.Addr { return pipeAddr{} }

func (p *pipe) Read(b []byte) (int, error) {
	n, err := p.read(b)
	if err != nil && err != io.EOF && err != io.ErrClosedPipe {
		err = &net.OpError{Op: "read", Net: "pipe", Err: err}
	}
	return n, err
}

func (p *pipe) read(b []byte) (n int, err error) {
	switch {
	case isClosedChan(p.localDone):
		return 0, io.ErrClosedPipe
	case isClosedChan(p.remoteDone):
		return 0, io.EOF
	case isClosedChan(p.readDeadline.wait()):
		return 0, os.ErrDeadlineExceeded
	}

	select {
	case bw := <-p.rdRx:
		nr := copy(b, bw)
		p.rdTx <- nr
		return nr, nil
	case <-p.localDone:
		return 0, io.ErrClosedPipe
	case <-p.remoteDone:
		return 0, io.EOF
	case <-p.readDeadline.wait():
		return 0, os.ErrDeadlineExceeded
	}
}

func (p *pipe) Write(b []byte) (int, error) {
	n, err := p.write(b)
	if err != nil && err != io.ErrClosedPipe {
		err = &net.OpError{Op: "write", Net: "pipe", Err: err}
	}
	return n, err
}

func (p *pipe) write(b []byte) (n int, err error) {
	switch {
	case isClosedChan(p.localDone):
		return 0, io.ErrClosedPipe
	case isClosedChan(p.remoteDone):
		return 0, io.ErrClosedPipe
	case isClosedChan(p.writeDeadline.wait()):
		return 0, os.ErrDeadlineExceeded
	}

	p.wrMu.Lock() // Ensure entirety of b is written together
	defer p.wrMu.Unlock()
	for once := true; once || len(b) > 0; once = false {
		select {
		case p.wrTx <- b:
			nw := <-p.wrRx
			b = b[nw:]
			n += nw
		case <-p.localDone:
			return n, io.ErrClosedPipe
		case <-p.remoteDone:
			return n, io.ErrClosedPipe
		case <-p.writeDeadline.wait():
			return n, os.ErrDeadlineExceeded
		}
	}
	return n, nil
}

func (p *pipe) SetDeadline(t time.Time) error {
	if isClosedChan(p.localDone) || isClosedChan(p.remoteDone) {
		return io.ErrClosedPipe
	}
	p.readDeadline.set(t)
	p.writeDeadline.set(t)
	return nil
}

func (p *pipe) SetReadDeadline(t time.Time) error {
	if isClosedChan(p.localDone) || isClosedChan(p.remoteDone) {
		return io.ErrClosedPipe
	}
	p.readDeadline.set(t)
	return nil
}

func (p *pipe) SetWriteDeadline(t time.Time) error {
	if isClosedChan(p.localDone) || isClosedChan(p.remoteDone) {
		return io.ErrClosedPipe
	}
	p.writeDeadline.set(t)
	return nil
}

func (p *pipe) Close() error {
	p.once.Do(func() { close(p.localDone) })
	return nil
}

var _ N.ReadWaiter = (*pipe)(nil)

func (p *pipe) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	p.readWaitOptions = options
	return false
}

func (p *pipe) WaitReadBuffer() (buffer *buf.Buffer, err error) {
	buffer, err = p.waitReadBuffer()
	if err != nil && err != io.EOF && err != io.ErrClosedPipe {
		err = &net.OpError{Op: "read", Net: "pipe", Err: err}
	}
	return
}

func (p *pipe) waitReadBuffer() (buffer *buf.Buffer, err error) {
	switch {
	case isClosedChan(p.localDone):
		return nil, io.ErrClosedPipe
	case isClosedChan(p.remoteDone):
		return nil, io.EOF
	case isClosedChan(p.readDeadline.wait()):
		return nil, os.ErrDeadlineExceeded
	}
	select {
	case bw := <-p.rdRx:
		buffer = p.readWaitOptions.NewBuffer()
		var nr int
		nr, err = buffer.Write(bw)
		if err != nil {
			buffer.Release()
			return
		}
		p.readWaitOptions.PostReturn(buffer)
		p.rdTx <- nr
		return
	case <-p.localDone:
		return nil, io.ErrClosedPipe
	case <-p.remoteDone:
		return nil, io.EOF
	case <-p.readDeadline.wait():
		return nil, os.ErrDeadlineExceeded
	}
}

func IsPipe(conn any) bool {
	_, ok := conn.(*pipe)
	return ok
}
