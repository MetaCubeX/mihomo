package reuse

import (
	"io"
	"sync"
	"sync/atomic"
	"time"

	snell "github.com/metacubex/mihomo/transport/singsnell"
	"github.com/metacubex/sing/common/buf"
	E "github.com/metacubex/sing/common/exceptions"
	N "github.com/metacubex/sing/common/network"
	"github.com/metacubex/sing/common/x/list"
)

const (
	PoolSize          = 10
	PoolMaxAge        = 180 * time.Second
	PoolTimerInterval = 20 * time.Second
	// Surge 6.7.0 (11520): SNConnectorV4::readServerEOFIfNotInReadState: closes a waiting connector after 0x80001 bytes are read after client EOF.
	WaitingDiscardLimit = 0x80001
	// snell-server v5.0.1: FUN_0013f020: writes ReplyError code 0x65 with message "Remote EOF" when the server side closes before replying.
	RemoteEOFCode    = 0x65
	RemoteEOFMessage = "Remote EOF"
)

type State uint8

const (
	StateReady State = iota
	StateActive
	StateWaiting
	StateClosed
)

type Session interface {
	io.Closer
	ReuseState() *atomic.Uint32
}

type poolEntry[S Session] struct {
	session S
	time    time.Time
}

type Pool[S Session] struct {
	access  sync.Mutex
	closed  bool
	entries list.List[*poolEntry[S]]
	stop    chan struct{}
	ticking bool
	drainWg sync.WaitGroup
}

func (p *Pool[S]) Init() {
	p.access.Lock()
	if p.stop == nil {
		p.entries.Init()
		p.stop = make(chan struct{})
	}
	p.access.Unlock()
}

func (p *Pool[S]) IsClosed() bool {
	p.access.Lock()
	closed := p.closed
	p.access.Unlock()
	return closed
}

func (p *Pool[S]) Take() (session S, found bool, closed bool) {
	p.access.Lock()
	closed = p.closed
	var expired []S
	now := time.Now()
	if !closed {
		for element := p.entries.Front(); element != nil; {
			next := element.Next()
			entry := element.Value
			state := State(entry.session.ReuseState().Load())
			if state == StateClosed {
				p.entries.Remove(element)
				element = next
				continue
			}
			if now.Sub(entry.time) > PoolMaxAge {
				p.entries.Remove(element)
				expired = append(expired, entry.session)
				element = next
				continue
			}
			if !found && state == StateReady && entry.session.ReuseState().CompareAndSwap(uint32(StateReady), uint32(StateActive)) {
				session = entry.session
				found = true
				p.entries.Remove(element)
				element = next
				continue
			}
			element = next
		}
	}
	p.access.Unlock()
	for _, expiredSession := range expired {
		expiredSession.Close()
	}
	return
}

func (p *Pool[S]) MoveToPool(session S, state State, drain bool) bool {
	p.access.Lock()
	closed := p.closed
	var expired []S
	now := time.Now()
	if !closed {
		for element := p.entries.Front(); element != nil; {
			next := element.Next()
			entry := element.Value
			entryState := State(entry.session.ReuseState().Load())
			if entryState == StateClosed {
				p.entries.Remove(element)
				element = next
				continue
			}
			if now.Sub(entry.time) > PoolMaxAge {
				p.entries.Remove(element)
				expired = append(expired, entry.session)
				element = next
				continue
			}
			element = next
		}
	}
	var added bool
	if !closed && p.stop != nil && p.entries.Len() < PoolSize {
		p.entries.PushBack(&poolEntry[S]{session: session, time: now})
		if state == StateWaiting && drain {
			p.drainWg.Add(1)
		}
		added = true
		if !p.ticking {
			p.ticking = true
			go p.ExpireLoop()
		}
	}
	p.access.Unlock()
	for _, expiredSession := range expired {
		expiredSession.Close()
	}
	if !added {
		session.Close()
	}
	return added
}

func (p *Pool[S]) ExpireLoop() {
	ticker := time.NewTicker(PoolTimerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			var expired []S
			now := time.Now()
			p.access.Lock()
			if p.closed {
				p.ticking = false
				p.access.Unlock()
				return
			}
			for element := p.entries.Front(); element != nil; {
				next := element.Next()
				entry := element.Value
				state := State(entry.session.ReuseState().Load())
				if state == StateClosed {
					p.entries.Remove(element)
					element = next
					continue
				}
				if now.Sub(entry.time) > PoolMaxAge {
					p.entries.Remove(element)
					expired = append(expired, entry.session)
					element = next
					continue
				}
				element = next
			}
			if p.entries.Len() == 0 {
				p.ticking = false
				p.access.Unlock()
				for _, expiredSession := range expired {
					expiredSession.Close()
				}
				return
			}
			p.access.Unlock()
			for _, expiredSession := range expired {
				expiredSession.Close()
			}
		case <-p.stop:
			return
		}
	}
}

func (p *Pool[S]) DrainDone() {
	p.drainWg.Done()
}

func (p *Pool[S]) Reset() {
	p.access.Lock()
	if p.closed {
		p.access.Unlock()
		return
	}
	var sessions []S
	for element := p.entries.Front(); element != nil; element = element.Next() {
		sessions = append(sessions, element.Value.session)
	}
	p.entries.Init()
	p.access.Unlock()
	for _, session := range sessions {
		session.Close()
	}
}

func (p *Pool[S]) Close() error {
	p.access.Lock()
	if p.closed {
		p.access.Unlock()
		return nil
	}
	p.closed = true
	var sessions []S
	for element := p.entries.Front(); element != nil; element = element.Next() {
		sessions = append(sessions, element.Value.session)
	}
	p.entries.Init()
	if p.stop != nil {
		close(p.stop)
	}
	p.access.Unlock()
	var closeErr error
	for _, session := range sessions {
		closeErr = E.Errors(closeErr, session.Close())
	}
	p.drainWg.Wait()
	return closeErr
}

type RecordReader interface {
	N.ExtendedReader
	N.ReadWaiter
	ReadRecord() (*buf.Buffer, error)
	NextRecord() (*buf.Buffer, error)
	SetCache(*buf.Buffer)
	ReleaseCache()
}

type RecordWriter interface {
	N.ExtendedWriter
	snell.VectorisedWriteCreator
	CreateVectorisedWriterFor(upstream N.VectorisedWriter) N.VectorisedWriter
	CreatePacketVectorisedWriterFor(upstream N.VectorisedWriter) N.VectorisedWriter
	WritePacketBuffer(buffer *buf.Buffer) error
	WriteZeroChunk() error
	FrontHeadroom() int
	RearHeadroom() int
	WriterMTU() int
	Upstream() any
}

func ParseReply(record *buf.Buffer) (*buf.Buffer, error) {
	reply, err := record.ReadByte()
	if err != nil {
		record.Release()
		return nil, err
	}
	switch reply {
	case snell.ReplyTunnel:
		if record.IsEmpty() {
			record.Release()
			return nil, nil
		}
		return record, nil
	case snell.ReplyError:
		defer record.Release()
		return nil, snell.ReadServerError(record)
	default:
		record.Release()
		return nil, E.Extend(snell.ErrUnexpectedReply, reply)
	}
}
