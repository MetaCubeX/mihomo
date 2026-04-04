package xhttp

import (
	"fmt"
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

func (e *reuseEntry) IsClosed() bool {
	return e.closed.Load()
}

func (e *reuseEntry) Close() {
	if !e.closed.CompareAndSwap(false, true) {
		return
	}
	httputils.CloseTransport(e.transport)
}

type reuseManager struct {
	cfg *ReuseConfig

	mu      sync.Mutex
	entries []*reuseEntry
}

func newReuseManager(cfg *ReuseConfig) *reuseManager {
	if cfg == nil {
		return nil
	}
	return &reuseManager{
		cfg:     cfg,
		entries: make([]*reuseEntry, 0),
	}
}

func (m *reuseManager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, entry := range m.entries {
		entry.Close()
	}
	m.entries = nil
	return nil
}

func (m *reuseManager) cleanupLocked(now time.Time) {
	kept := m.entries[:0]
	for _, entry := range m.entries {
		if entry.IsClosed() {
			continue
		}
		if entry.leftRequests.Load() <= 0 && entry.openUsage.Load() == 0 {
			entry.Close()
			continue
		}
		if !entry.unreusableAt.IsZero() && now.After(entry.unreusableAt) && entry.openUsage.Load() == 0 {
			entry.Close()
			continue
		}
		kept = append(kept, entry)
	}
	m.entries = kept
}

func (m *reuseManager) release(entry *reuseEntry) {
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
			entry.Close()
		}
	}
}

func (m *reuseManager) resolvedMaxConcurrency() int {
	if m.cfg == nil {
		return 0
	}
	v, err := resolveRangeValue(m.cfg.MaxConcurrency, 0)
	if err != nil {
		return 0
	}
	return v
}

func (m *reuseManager) resolvedMaxConnections() int {
	if m.cfg == nil {
		return 0
	}
	v, err := resolveRangeValue(m.cfg.MaxConnections, 0)
	if err != nil {
		return 0
	}
	return v
}

func (m *reuseManager) pickLocked() *reuseEntry {
	maxConcurrency := m.resolvedMaxConcurrency()

	var best *reuseEntry
	for _, entry := range m.entries {
		if entry.IsClosed() {
			continue
		}
		if entry.leftRequests.Load() <= 0 {
			continue
		}
		if entry.maxReuseTimes > 0 && entry.reuseCount.Load() >= entry.maxReuseTimes {
			continue
		}
		if maxConcurrency > 0 && int(entry.openUsage.Load()) >= maxConcurrency {
			continue
		}
		if best == nil || entry.openUsage.Load() < best.openUsage.Load() {
			best = entry
		}
	}
	return best
}

func (m *reuseManager) canCreateLocked() bool {
	maxConnections := m.resolvedMaxConnections()
	if maxConnections <= 0 {
		return true
	}
	return len(m.entries) < maxConnections
}

func (m *reuseManager) newEntryLocked(
	makeTransport TransportMaker,
	now time.Time,
) *reuseEntry {
	transport := makeTransport()
	entry := &reuseEntry{transport: transport}

	if m.cfg != nil {
		hMaxRequestTimes, hMaxReusableSecs, err := m.cfg.ResolveEntryConfig()
		if err == nil {
			if hMaxRequestTimes > 0 {
				entry.leftRequests.Store(int32(hMaxRequestTimes))
			} else {
				entry.leftRequests.Store(1<<30 - 1)
			}
			if hMaxReusableSecs > 0 {
				entry.unreusableAt = now.Add(time.Duration(hMaxReusableSecs) * time.Second)
			}
		} else {
			entry.leftRequests.Store(1<<30 - 1)
		}

		cMaxReuseTimes, err := m.cfg.ResolveConnReuseConfig()
		if err == nil && cMaxReuseTimes > 0 {
			entry.maxReuseTimes = int32(cMaxReuseTimes)
		}
	} else {
		entry.leftRequests.Store(1<<30 - 1)
	}

	m.entries = append(m.entries, entry)
	return entry
}

func (m *reuseManager) getOrCreate(
	makeTransport TransportMaker,
) (*reuseEntry, error) {
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	m.cleanupLocked(now)

	entry := m.pickLocked()
	reused := entry != nil

	if entry == nil {
		if !m.canCreateLocked() {
			return nil, fmt.Errorf("manager: no available connection")
		}
		entry = m.newEntryLocked(makeTransport, now)
	}

	if reused {
		entry.reuseCount.Add(1)
	}

	entry.openUsage.Add(1)
	if entry.leftRequests.Load() > 0 {
		entry.leftRequests.Add(-1)
	}

	return entry, nil
}
