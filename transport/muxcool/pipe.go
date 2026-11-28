package muxcool

import (
	"io"
	"sync"
)

// sessionBufLimit —— 每个子流入站缓冲上限。短突发在此额度内不阻塞 mux 读环(缓解 HoL);
// 超过则对该子流施加背压(读环阻塞在该子流的 Write 上,与 Xray 的 buf pipe 语义一致)。
const sessionBufLimit = 64 * 1024

// bufPipe —— 带缓冲上限的内存管道。相比 io.Pipe(零缓冲、同步),Write 在缓冲未满时立即返回,
// 使 mux 读环不被慢速本地目标同步阻塞。实现 io.Reader / io.WriteCloser。
type bufPipe struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	limit  int
	closed bool
	rerr   error
}

func newBufPipe(limit int) *bufPipe {
	p := &bufPipe{limit: limit}
	p.cond = sync.NewCond(&p.mu)
	return p
}

// Write 追加数据;缓冲满则阻塞等待空间(背压)。关闭后返回 ErrClosedPipe。
func (p *bufPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	written := 0
	for len(b) > 0 {
		for len(p.buf) >= p.limit && !p.closed {
			p.cond.Wait()
		}
		if p.closed {
			return written, io.ErrClosedPipe
		}
		space := p.limit - len(p.buf)
		n := len(b)
		if n > space {
			n = space
		}
		p.buf = append(p.buf, b[:n]...)
		b = b[n:]
		written += n
		p.cond.Broadcast()
	}
	return written, nil
}

// Read 排空缓冲;空且未关则阻塞;关闭且排空后返回 EOF(或 CloseWithError 设的错误)。
func (p *bufPipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.buf) == 0 && !p.closed {
		p.cond.Wait()
	}
	if len(p.buf) == 0 {
		if p.rerr != nil {
			return 0, p.rerr
		}
		return 0, io.EOF
	}
	n := copy(b, p.buf)
	if n == len(p.buf) {
		p.buf = nil // 排空,释放底层数组
	} else {
		p.buf = p.buf[n:]
	}
	p.cond.Broadcast()
	return n, nil
}

func (p *bufPipe) Close() error { return p.CloseWithError(nil) }

func (p *bufPipe) CloseWithError(err error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		p.rerr = err
		p.cond.Broadcast()
	}
	return nil
}
