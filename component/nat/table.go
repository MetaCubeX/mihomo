package nat

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/common/xsync"
	C "github.com/metacubex/mihomo/constant"

	M "github.com/metacubex/sing/common/metadata"
)

type Table struct {
	mapping xsync.Map[string, *sourceGroup]
}

type sourceGroup struct {
	mu          sync.Mutex
	config      C.UDPConfig
	sessions    map[C.UDPSessionKey]C.PacketSender
	independent atomic.Pointer[C.PacketSender]
	local       map[string]*localConn
	closing     bool
	done        chan struct{}
	previous    <-chan struct{}
	active      sync.WaitGroup
}

type localConn struct {
	ready chan struct{}
	conn  *net.UDPConn
	err   error
}

func (t *Table) LoadSession(source string, origin M.Socksaddr) (C.PacketSender, C.NatSource, bool) {
	group, loaded := t.mapping.Load(source)
	if !loaded {
		return nil, nil, false
	}
	if group.config.Mapping == C.UDPEndpointIndependent {
		// EI has exactly one session. Publish its immutable sender separately
		// so the default mode needs neither a destination key nor the group lock.
		if sender := group.independent.Load(); sender != nil {
			return *sender, group, true
		}
		return nil, nil, false
	}
	group.mu.Lock()
	sender, loaded := group.sessions[C.NewUDPSessionKey(source, group.config.Mapping, origin)]
	group.mu.Unlock()
	if !loaded {
		return nil, nil, false
	}
	return sender, group, true
}

func (t *Table) GetOrCreateSession(source string, origin M.Socksaddr, config C.UDPConfig, maker func(C.UDPSessionKey, C.NatSource, C.UDPConfig) C.PacketSender) (C.PacketSender, C.NatSource, bool) {
	for {
		group, _ := t.mapping.Compute(source, func(group *sourceGroup, loaded bool) (*sourceGroup, xsync.ComputeOp) {
			var previous <-chan struct{}
			if loaded {
				group.mu.Lock()
				closing := group.closing
				group.mu.Unlock()
				if !closing {
					return group, xsync.CancelOp
				}
				previous = group.done
			}
			return &sourceGroup{
				config:   config,
				sessions: make(map[C.UDPSessionKey]C.PacketSender),
				local:    make(map[string]*localConn),
				done:     make(chan struct{}),
				previous: previous,
			}, xsync.UpdateOp
		})
		group.mu.Lock()
		if group.closing {
			group.mu.Unlock()
			continue
		}
		key := C.NewUDPSessionKey(source, group.config.Mapping, origin)
		sender, loaded := group.sessions[key]
		if !loaded {
			sender = maker(key, group, group.config)
			group.sessions[key] = sender
			if group.config.Mapping == C.UDPEndpointIndependent {
				group.independent.Store(&sender)
			}
		}
		group.mu.Unlock()
		return sender, group, loaded
	}
}

// DeleteSession only removes its own sender. A delayed read loop must not
// remove a replacement session or close sockets still used by its siblings.
func (t *Table) DeleteSession(key C.UDPSessionKey, sender C.PacketSender) bool {
	group, loaded := t.mapping.Load(key.Source)
	if !loaded {
		return false
	}
	group.mu.Lock()
	current, loaded := group.sessions[key]
	if group.closing || !loaded || current != sender {
		group.mu.Unlock()
		return false
	}
	delete(group.sessions, key)
	last := len(group.sessions) == 0
	if last {
		group.closing = true
		// Stop new fast-path lookups before waiting for local sockets. A lookup
		// that already loaded the sender may race Close, just like a map lookup.
		group.independent.Store(nil)
	}
	group.mu.Unlock()
	if last {
		t.closeSource(key.Source, group)
	}
	return true
}

func (t *Table) closeSource(source string, group *sourceGroup) {
	// Even a replacement that never opened a socket must preserve the barrier
	// for its successor; an older generation may still own the local address.
	if group.previous != nil {
		<-group.previous
	}
	group.active.Wait()
	for _, local := range group.local {
		if local.conn != nil {
			_ = local.conn.Close()
		}
	}
	t.mapping.Compute(source, func(current *sourceGroup, loaded bool) (*sourceGroup, xsync.ComputeOp) {
		if !loaded || current != group {
			return current, xsync.CancelOp
		}
		return current, xsync.DeleteOp
	})
	close(group.done)
}

func (g *sourceGroup) WithLocalConn(remote string, maker func() (*net.UDPConn, error), write func(*net.UDPConn) (int, error)) (int, error) {
	g.mu.Lock()
	if g.closing {
		g.mu.Unlock()
		return 0, net.ErrClosed
	}
	// Admission and closing use the same lock, so Wait cannot race a new Add.
	g.active.Add(1)
	local, loaded := g.local[remote]
	if !loaded {
		local = &localConn{ready: make(chan struct{})}
		g.local[remote] = local
	}
	g.mu.Unlock()
	defer g.active.Done()
	if !loaded {
		// Only the reply goroutine waits. processUDP can publish the replacement
		// session immediately, but local sockets cannot bind until old ones close.
		if g.previous != nil {
			<-g.previous
		}
		local.conn, local.err = maker()
		g.mu.Lock()
		if local.err != nil {
			// Existing waiters receive this creation's error; a later packet can
			// make its own explicit creation attempt, as before.
			delete(g.local, remote)
		}
		close(local.ready)
		g.mu.Unlock()
	} else {
		<-local.ready
	}
	if local.err != nil {
		return 0, local.err
	}
	return write(local.conn)
}

// New returns an empty NAT table.
func New() *Table {
	return &Table{}
}
