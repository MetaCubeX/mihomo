package statistic

import (
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/deque"
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

	snapshotMu        sync.Mutex
	snapshotStreams   map[*SnapshotStream]struct{}
	closedConnections deque.Deque[*TrackerInfo]
}

func (m *Manager) Join(c Tracker) {
	m.connections.Store(c.ID(), c)
}

func (m *Manager) Leave(c Tracker) {
	tracker, loaded := m.connections.LoadAndDelete(c.ID())
	if !loaded {
		return
	}

	m.snapshotMu.Lock()
	if len(m.snapshotStreams) != 0 {
		m.closedConnections.PushBack(tracker.Info())
		for stream := range m.snapshotStreams {
			select {
			case stream.updates <- struct{}{}:
			default:
			}
		}
	}
	m.snapshotMu.Unlock()
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
	cursor  int
	updates chan struct{}
}

func (m *Manager) NewSnapshotStream() *SnapshotStream {
	m.snapshotMu.Lock()
	defer m.snapshotMu.Unlock()

	stream := &SnapshotStream{
		manager: m,
		cursor:  m.closedConnections.Len(),
		updates: make(chan struct{}, 1),
	}
	if m.snapshotStreams == nil {
		m.snapshotStreams = map[*SnapshotStream]struct{}{}
	}
	m.snapshotStreams[stream] = struct{}{}
	return stream
}

func (s *SnapshotStream) Snapshot() *Snapshot {
	snapshot := s.manager.Snapshot()
	m := s.manager
	m.snapshotMu.Lock()

	closedCount := m.closedConnections.Len()
	select {
	case <-s.updates:
	default:
	}
	if s.cursor == closedCount {
		m.snapshotMu.Unlock()
		return snapshot
	}

	closedConnections := make([]*TrackerInfo, 0, closedCount-s.cursor)
	for i := s.cursor; i < closedCount; i++ {
		closedConnections = append(closedConnections, m.closedConnections.At(i))
	}
	s.cursor = closedCount
	m.pruneClosedConnectionsLocked()
	m.snapshotMu.Unlock()

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

// Updates reports when closed connections are ready for the next snapshot.
func (s *SnapshotStream) Updates() <-chan struct{} {
	return s.updates
}

func (s *SnapshotStream) Close() {
	m := s.manager
	m.snapshotMu.Lock()
	if _, exists := m.snapshotStreams[s]; exists {
		delete(m.snapshotStreams, s)
		m.pruneClosedConnectionsLocked()
	}
	m.snapshotMu.Unlock()
}

func (m *Manager) pruneClosedConnectionsLocked() {
	closedCount := m.closedConnections.Len()
	pruneCount := closedCount
	for stream := range m.snapshotStreams {
		if stream.cursor < pruneCount {
			pruneCount = stream.cursor
		}
	}
	if pruneCount == 0 {
		return
	}
	if pruneCount == closedCount {
		m.closedConnections = deque.Deque[*TrackerInfo]{}
	} else {
		for i := 0; i < pruneCount; i++ {
			m.closedConnections.PopFront()
		}
	}
	for stream := range m.snapshotStreams {
		stream.cursor -= pruneCount
	}
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
