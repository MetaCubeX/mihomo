package tunnel

import (
	"sync"
	"sync/atomic"
	"time"
)

var DefaultManager *Manager

func init() {
	DefaultManager = &Manager{}

	go DefaultManager.handle()
}

type Manager struct {
	connections   sync.Map
	uploadTemp    int64
	downloadTemp  int64
	uploadBlip    int64
	downloadBlip  int64
	uploadTotal   int64
	downloadTotal int64
}

func (m *Manager) Join(c tracker) {
	m.connections.Store(c.ID(), c)
}

func (m *Manager) Leave(c tracker) {
	m.connections.Delete(c.ID())
}

func (m *Manager) PushUploaded(size int64) {
	atomic.AddInt64(&m.uploadTemp, size)
	atomic.AddInt64(&m.uploadTotal, size)
}

func (m *Manager) PushDownloaded(size int64) {
	atomic.AddInt64(&m.downloadTemp, size)
	atomic.AddInt64(&m.downloadTotal, size)
}

func (m *Manager) Now() (up int64, down int64) {
	return atomic.LoadInt64(&m.uploadBlip), atomic.LoadInt64(&m.downloadBlip)
}

func (m *Manager) Snapshot() *Snapshot {
	connections := []tracker{}
	m.connections.Range(func(key, value interface{}) bool {
		connections = append(connections, value.(tracker))
		return true
	})

	return &Snapshot{
		UploadTotal:   atomic.LoadInt64(&m.uploadTotal),
		DownloadTotal: atomic.LoadInt64(&m.downloadTotal),
		Connections:   connections,
	}
}

func (m *Manager) ResetStatistic() {
	m.uploadTemp = 0
	m.uploadBlip = 0
	m.uploadTotal = 0
	m.downloadTemp = 0
	m.downloadBlip = 0
	m.downloadTotal = 0
}

func (m *Manager) handle() {
	ticker := time.NewTicker(time.Second)

	for range ticker.C {
		atomic.StoreInt64(&m.uploadBlip, atomic.LoadInt64(&m.uploadTemp))
		atomic.StoreInt64(&m.uploadTemp, 0)
		atomic.StoreInt64(&m.downloadBlip, atomic.LoadInt64(&m.downloadTemp))
		atomic.StoreInt64(&m.downloadTemp, 0)
	}
}

type Snapshot struct {
	DownloadTotal int64     `json:"downloadTotal"`
	UploadTotal   int64     `json:"uploadTotal"`
	Connections   []tracker `json:"connections"`
}
