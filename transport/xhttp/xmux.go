package xhttp

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/common/httputils"
)

type xmuxEntry struct {
	uploadTransport   http.RoundTripper
	downloadTransport http.RoundTripper

	openUsage    atomic.Int32
	leftRequests atomic.Int32
	unreusableAt time.Time

	closed atomic.Bool
}

func (e *xmuxEntry) IsClosed() bool {
	return e.closed.Load()
}

func (e *xmuxEntry) Close() {
	if !e.closed.CompareAndSwap(false, true) {
		return
	}
	httputils.CloseTransport(e.uploadTransport)
	if e.downloadTransport != e.uploadTransport {
		httputils.CloseTransport(e.downloadTransport)
	}
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
		if entry.leftRequests.Load() <= 0 || (!entry.unreusableAt.IsZero() && now.After(entry.unreusableAt)) {
			entry.Close()
		}
	}
}

func (m *xmuxManager) pickLocked() *xmuxEntry {
	maxConcurrency := 0
	if m.cfg != nil {
		maxConcurrency = m.cfg.MaxConcurrency
	}

	var best *xmuxEntry
	for _, entry := range m.entries {
		if entry.IsClosed() {
			continue
		}
		if entry.leftRequests.Load() <= 0 {
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
	if m.cfg == nil || m.cfg.MaxConnections <= 0 {
		return true
	}
	return len(m.entries) < m.cfg.MaxConnections
}

func (m *xmuxManager) newEntryLocked(
	makeTransport TransportMaker,
	makeDownloadTransport TransportMaker,
	now time.Time,
) *xmuxEntry {
	uploadTransport := makeTransport()
	downloadTransport := uploadTransport
	if makeDownloadTransport != nil {
		downloadTransport = makeDownloadTransport()
	}

	entry := &xmuxEntry{
		uploadTransport:   uploadTransport,
		downloadTransport: downloadTransport,
	}

	if m.cfg != nil {
		if m.cfg.HMaxRequestTimes > 0 {
			entry.leftRequests.Store(int32(m.cfg.HMaxRequestTimes))
		} else {
			entry.leftRequests.Store(1<<30 - 1)
		}
		if m.cfg.HMaxReusableSecs > 0 {
			entry.unreusableAt = now.Add(time.Duration(m.cfg.HMaxReusableSecs) * time.Second)
		}
	} else {
		entry.leftRequests.Store(1<<30 - 1)
	}

	m.entries = append(m.entries, entry)
	return entry
}

func (m *xmuxManager) getOrCreate(
	makeTransport TransportMaker,
	makeDownloadTransport TransportMaker,
) (*xmuxEntry, error) {
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	m.cleanupLocked(now)

	entry := m.pickLocked()
	if entry == nil {
		if !m.canCreateLocked() && len(m.entries) > 0 {
			var best *xmuxEntry
			for _, e := range m.entries {
				if e.IsClosed() {
					continue
				}
				if e.leftRequests.Load() <= 0 {
					continue
				}
				if best == nil || e.openUsage.Load() < best.openUsage.Load() {
					best = e
				}
			}
			entry = best
		} else {
			entry = m.newEntryLocked(makeTransport, makeDownloadTransport, now)
		}
	}

	if entry == nil {
		entry = m.newEntryLocked(makeTransport, makeDownloadTransport, now)
	}

	entry.openUsage.Add(1)
	if entry.leftRequests.Load() > 0 {
		entry.leftRequests.Add(-1)
	}

	return entry, nil
}
