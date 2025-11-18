package xhttp

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type clientSlot struct {
	client           *http.Client
	transport        http.RoundTripper
	cfg              normalizedXmux
	remainingUses    int32
	remainingRequest int32
	expiry           time.Time
	openUsage        atomic.Int32
	closeOnce        sync.Once
}

func (s *clientSlot) shouldDrop(now time.Time) bool {
	if !s.expiry.IsZero() && now.After(s.expiry) {
		return true
	}
	if s.remainingUses == 0 && s.cfg.reuseRange != (Range{}) {
		return true
	}
	if s.remainingRequest == 0 && s.cfg.requestRange != (Range{}) {
		return true
	}
	return false
}

func (s *clientSlot) release() {
	s.openUsage.Add(-1)
}

func (s *clientSlot) close() {
	s.closeOnce.Do(func() {
		if s.transport != nil {
			if closer, ok := s.transport.(interface{ Close() error }); ok {
				_ = closer.Close()
			}
		}
		if s.client != nil {
			s.client.CloseIdleConnections()
		}
	})
}

type xmuxManager struct {
	key       string
	cfg       normalizedXmux
	newClient func() (*clientSlot, error)

	mu      sync.Mutex
	clients []*clientSlot
}

func (m *xmuxManager) acquire() (*clientSlot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	j := 0
	for _, slot := range m.clients {
		if slot.shouldDrop(now) && slot.openUsage.Load() == 0 {
			slot.close()
			continue
		}
		m.clients[j] = slot
		j++
	}
	m.clients = m.clients[:j]

	var candidate *clientSlot
	for _, slot := range m.clients {
		if m.cfg.maxConcurrency > 0 && slot.openUsage.Load() >= m.cfg.maxConcurrency {
			continue
		}
		candidate = slot
		break
	}

	if candidate == nil {
		if m.cfg.maxConnections == 0 || len(m.clients) < m.cfg.maxConnections {
			slot, err := m.newClient()
			if err != nil {
				return nil, err
			}
			m.clients = append(m.clients, slot)
			candidate = slot
		} else if len(m.clients) > 0 {
			candidate = m.clients[0]
		}
	}

	if candidate == nil {
		return nil, nil
	}

	candidate.openUsage.Add(1)
	if candidate.remainingUses > 0 {
		candidate.remainingUses--
	}
	if candidate.remainingRequest > 0 {
		candidate.remainingRequest--
	}
	return candidate, nil
}

var xmuxRegistry sync.Map

func acquireClient(key string, cfg normalizedXmux, factory func() (*clientSlot, error)) (*clientSlot, error) {
	managerAny, ok := xmuxRegistry.Load(key)
	if !ok {
		manager := &xmuxManager{
			key:       key,
			cfg:       cfg,
			newClient: factory,
		}
		actual, _ := xmuxRegistry.LoadOrStore(key, manager)
		managerAny = actual
	}

	manager := managerAny.(*xmuxManager)
	slot, err := manager.acquire()
	if err != nil {
		return nil, err
	}
	if slot == nil {
		return nil, nil
	}
	return slot, nil
}
