package xhttp

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/common/httputils"
)

type xmuxEntry struct {
	transport http.RoundTripper

	openUsage     atomic.Int32
	leftRequests  atomic.Int32
	reuseCount    atomic.Int32
	maxReuseTimes int32
	unreusableAt  time.Time

	closed atomic.Bool
}

func (e *xmuxEntry) IsClosed() bool {
	return e.closed.Load()
}

func (e *xmuxEntry) Close() {
	if !e.closed.CompareAndSwap(false, true) {
		return
	}
	httputils.CloseTransport(e.transport)

}

type xmuxManager struct {
	cfg *XMuxConfig

	mu      sync.Mutex
	entries []*xmuxEntry
}

func newXMuxManager(cfg *XMuxConfig) *xmuxManager {
	if cfg == nil {
		return nil
	}
	return &xmuxManager{
		cfg:     cfg,
		entries: make([]*xmuxEntry, 0),
	}
}

func (m *xmuxManager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, entry := range m.entries {
		entry.Close()
	}
	m.entries = nil
}

func (m *xmuxManager) cleanupLocked(now time.Time) {
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

func (m *xmuxManager) release(entry *xmuxEntry) {
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

func (m *xmuxManager) resolvedMaxConcurrency() int {
	if m.cfg == nil {
		return 0
	}
	v, err := resolveRangeValue(m.cfg.MaxConcurrency, 0)
	if err != nil {
		return 0
	}
	return v
}

func (m *xmuxManager) resolvedMaxConnections() int {
	if m.cfg == nil {
		return 0
	}
	v, err := resolveRangeValue(m.cfg.MaxConnections, 0)
	if err != nil {
		return 0
	}
	return v
}

func (m *xmuxManager) pickLocked() *xmuxEntry {
	maxConcurrency := m.resolvedMaxConcurrency()

	var best *xmuxEntry
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

func (m *xmuxManager) canCreateLocked() bool {
	maxConnections := m.resolvedMaxConnections()
	if maxConnections <= 0 {
		return true
	}
	return len(m.entries) < maxConnections
}

func (m *xmuxManager) newEntryLocked(
	makeTransport TransportMaker,
	now time.Time,
) *xmuxEntry {
	transport := makeTransport()
	entry := &xmuxEntry{transport: transport}

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

func (m *xmuxManager) getOrCreate(
	makeTransport TransportMaker,
) (*xmuxEntry, error) {
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	m.cleanupLocked(now)

	entry := m.pickLocked()
	reused := entry != nil

	if entry == nil {
		if !m.canCreateLocked() {
			return nil, fmt.Errorf("xmux: no available connection")
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
