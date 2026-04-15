package xhttp

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/httputils"

	"github.com/metacubex/http"
)

type reuseEntry struct {
	transport http.RoundTripper

	openUsage     atomic.Int32
	leftRequests  atomic.Int32
	reuseCount    atomic.Int32
	maxReuseTimes int32
	unreusableAt  time.Time

	closed atomic.Bool
}

func (entry *reuseEntry) isClosed() bool {
	return entry.closed.Load()
}

func (entry *reuseEntry) close() {
	if !entry.closed.CompareAndSwap(false, true) {
		return
	}
	httputils.CloseTransport(entry.transport)
}

type ReuseTransport struct {
	entry   *reuseEntry
	removed atomic.Bool
}

func (rt *ReuseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt.entry.transport.RoundTrip(req)
}

func (rt *ReuseTransport) Close() error {
	if !rt.removed.CompareAndSwap(false, true) {
		return nil
	}
	rt.entry.release()
	return nil
}

var _ http.RoundTripper = (*ReuseTransport)(nil)

type ReuseManager struct {
	maxConcurrency   int
	maxConnections   int
	cMaxReuseTimes   Range
	hMaxRequestTimes Range
	hMaxReusableSecs Range
	maker            TransportMaker
	mu               sync.Mutex
	entries          []*reuseEntry
}

func NewReuseManager(cfg *ReuseConfig, makeTransport TransportMaker) (*ReuseManager, error) {
	if cfg == nil {
		return nil, nil
	}
	concurrency, connections, err := cfg.ResolveManagerConfig()
	if err != nil {
		return nil, err
	}
	cMaxReuseTimes, hMaxRequestTimes, hMaxReusableSecs, err := cfg.ResolveEntryConfig()
	if err != nil {
		return nil, err
	}
	return &ReuseManager{
		maxConcurrency:   concurrency.Rand(),
		maxConnections:   connections.Rand(),
		cMaxReuseTimes:   cMaxReuseTimes,
		hMaxRequestTimes: hMaxRequestTimes,
		hMaxReusableSecs: hMaxReusableSecs,
		maker:            makeTransport,
		entries:          make([]*reuseEntry, 0),
	}, nil
}

func (m *ReuseManager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, entry := range m.entries {
		entry.close()
	}
	m.entries = nil
	return nil
}

func (m *ReuseManager) cleanupLocked(now time.Time) {
	kept := m.entries[:0]
	for _, entry := range m.entries {
		if entry.isClosed() {
			continue
		}
		if entry.leftRequests.Load() <= 0 && entry.openUsage.Load() == 0 {
			entry.close()
			continue
		}
		if !entry.unreusableAt.IsZero() && now.After(entry.unreusableAt) && entry.openUsage.Load() == 0 {
			entry.close()
			continue
		}
		kept = append(kept, entry)
	}
	m.entries = kept
}

func (entry *reuseEntry) release() {
	if entry == nil {
		return
	}
	remaining := entry.openUsage.Add(-1)
	if remaining < 0 {
		entry.openUsage.Store(0)
		remaining = 0
	}

	if remaining == 0 {
		now := time.Now()
		if entry.leftRequests.Load() <= 0 ||
			(entry.maxReuseTimes > 0 && entry.reuseCount.Load() >= entry.maxReuseTimes) ||
			(!entry.unreusableAt.IsZero() && now.After(entry.unreusableAt)) {
			entry.close()
		}
	}
}

func (m *ReuseManager) pickLocked() *reuseEntry {
	var best *reuseEntry
	for _, entry := range m.entries {
		if entry.isClosed() {
			continue
		}
		if entry.leftRequests.Load() <= 0 {
			continue
		}
		if entry.maxReuseTimes > 0 && entry.reuseCount.Load() >= entry.maxReuseTimes {
			continue
		}
		if m.maxConcurrency > 0 && int(entry.openUsage.Load()) >= m.maxConcurrency {
			continue
		}
		if best == nil || entry.openUsage.Load() < best.openUsage.Load() {
			best = entry
		}
	}
	return best
}

func (m *ReuseManager) shouldCreateLocked() bool {
	if len(m.entries) == 0 {
		return true
	}
	if m.maxConnections > 0 {
		return len(m.entries) < m.maxConnections
	}
	return false
}

func (m *ReuseManager) newEntryLocked(transport http.RoundTripper, now time.Time) *reuseEntry {
	entry := &reuseEntry{transport: transport}

	if m.hMaxRequestTimes.Max > 0 {
		entry.leftRequests.Store(int32(m.hMaxRequestTimes.Rand()))
	} else {
		entry.leftRequests.Store(1<<30 - 1)
	}
	if m.hMaxReusableSecs.Max > 0 {
		entry.unreusableAt = now.Add(time.Duration(m.hMaxReusableSecs.Rand()) * time.Second)
	}
	if m.cMaxReuseTimes.Max > 0 {
		entry.maxReuseTimes = int32(m.cMaxReuseTimes.Rand())
	}

	m.entries = append(m.entries, entry)
	return entry
}

func (m *ReuseManager) GetTransport() http.RoundTripper {
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	m.cleanupLocked(now)

	var entry *reuseEntry
	if !m.shouldCreateLocked() {
		entry = m.pickLocked()
	}
	reused := entry != nil

	if entry == nil {
		transport := m.maker()
		entry = m.newEntryLocked(transport, now)
	}

	if reused {
		entry.reuseCount.Add(1)
	}

	entry.openUsage.Add(1)
	if entry.leftRequests.Load() > 0 {
		entry.leftRequests.Add(-1)
	}

	return &ReuseTransport{entry: entry}
}
