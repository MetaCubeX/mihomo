package statistic

import (
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/memory"

	"github.com/gofrs/uuid/v5"
)

var DefaultManager *Manager

func init() {
	DefaultManager = &Manager{
		uploadTemp:    atomic.NewInt64(0),
		downloadTemp:  atomic.NewInt64(0),
		uploadBlip:    atomic.NewInt64(0),
		downloadBlip:  atomic.NewInt64(0),
		uploadTotal:   atomic.NewInt64(0),
		downloadTotal: atomic.NewInt64(0),
		pid:           int32(os.Getpid()),
	}

	go DefaultManager.handle()
}

type Manager struct {
	connections   xsync.Map[string, Tracker]
	uploadTemp    atomic.Int64
	downloadTemp  atomic.Int64
	uploadBlip    atomic.Int64
	downloadBlip  atomic.Int64
	uploadTotal   atomic.Int64
	downloadTotal atomic.Int64
	pid           int32
	memory        uint64

	snapshotStreamsMu sync.RWMutex
	snapshotStreams   map[*SnapshotStream]struct{}
}

func (m *Manager) Join(c Tracker) {
	m.connections.Store(c.ID(), c)
}

func (m *Manager) Leave(c Tracker) {
	tracker, loaded := m.connections.LoadAndDelete(c.ID())
	if !loaded {
		return
	}

	info := tracker.Info()
	m.snapshotStreamsMu.RLock()
	defer m.snapshotStreamsMu.RUnlock()
	for stream := range m.snapshotStreams {
		stream.pushClosed(info)
	}
}

func (m *Manager) Get(id string) (c Tracker) {
	if value, ok := m.connections.Load(id); ok {
		c = value
	}
	return
}

func (m *Manager) Range(f func(c Tracker) bool) {
	m.connections.Range(func(key string, value Tracker) bool {
		return f(value)
	})
}

func (m *Manager) PushUploaded(size int64) {
	m.uploadTemp.Add(size)
	m.uploadTotal.Add(size)
}

func (m *Manager) PushDownloaded(size int64) {
	m.downloadTemp.Add(size)
	m.downloadTotal.Add(size)
}

func (m *Manager) Now() (up int64, down int64) {
	return m.uploadBlip.Load(), m.downloadBlip.Load()
}

func (m *Manager) Total() (up, down int64) {
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}

func (m *Manager) Memory() uint64 {
	m.updateMemory()
	return m.memory
}

func (m *Manager) Snapshot() *Snapshot {
	var connections []*TrackerInfo
	m.Range(func(c Tracker) bool {
		connections = append(connections, c.Info())
		return true
	})
	return &Snapshot{
		UploadTotal:   m.uploadTotal.Load(),
		DownloadTotal: m.downloadTotal.Load(),
		Connections:   connections,
		Memory:        m.memory,
	}
}

// SnapshotStream includes connections closed between snapshots in the next snapshot.
type SnapshotStream struct {
	manager *Manager
	mu      sync.Mutex
	pending []*TrackerInfo
}

func (m *Manager) NewSnapshotStream() *SnapshotStream {
	stream := &SnapshotStream{manager: m}
	m.snapshotStreamsMu.Lock()
	if m.snapshotStreams == nil {
		m.snapshotStreams = map[*SnapshotStream]struct{}{}
	}
	m.snapshotStreams[stream] = struct{}{}
	m.snapshotStreamsMu.Unlock()
	return stream
}

func (s *SnapshotStream) Snapshot() *Snapshot {
	snapshot := s.manager.Snapshot()

	s.mu.Lock()
	if len(s.pending) == 0 {
		s.mu.Unlock()
		return snapshot
	}
	closedConnections := s.pending
	s.pending = nil
	s.mu.Unlock()

	activeConnections := make(map[uuid.UUID]struct{}, len(snapshot.Connections))
	for _, connection := range snapshot.Connections {
		activeConnections[connection.UUID] = struct{}{}
	}
	for _, connection := range closedConnections {
		if _, exists := activeConnections[connection.UUID]; !exists {
			snapshot.Connections = append(snapshot.Connections, connection)
		}
	}
	return snapshot
}

func (s *SnapshotStream) Close() {
	s.manager.snapshotStreamsMu.Lock()
	delete(s.manager.snapshotStreams, s)
	s.manager.snapshotStreamsMu.Unlock()
}

func (s *SnapshotStream) pushClosed(connection *TrackerInfo) {
	s.mu.Lock()
	s.pending = append(s.pending, connection)
	s.mu.Unlock()
}

func (m *Manager) updateMemory() {
	stat, err := memory.GetMemoryInfo(m.pid)
	if err != nil {
		return
	}
	m.memory = stat.RSS
}

func (m *Manager) ResetStatistic() {
	m.uploadTemp.Store(0)
	m.uploadBlip.Store(0)
	m.uploadTotal.Store(0)
	m.downloadTemp.Store(0)
	m.downloadBlip.Store(0)
	m.downloadTotal.Store(0)
}

func (m *Manager) handle() {
	ticker := time.NewTicker(time.Second)

	for range ticker.C {
		m.uploadBlip.Store(m.uploadTemp.Swap(0))
		m.downloadBlip.Store(m.downloadTemp.Swap(0))
	}
}

type Snapshot struct {
	DownloadTotal int64          `json:"downloadTotal"`
	UploadTotal   int64          `json:"uploadTotal"`
	Connections   []*TrackerInfo `json:"connections"`
	Memory        uint64         `json:"memory"`
}
