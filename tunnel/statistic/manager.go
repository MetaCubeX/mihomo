package statistic

import (
	"encoding/json"
	"github.com/shirou/gopsutil/v3/process"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/log"
	"github.com/puzpuzpuz/xsync/v3"
)

var Processor *process.Process
var ChannelManager map[string]*Manager
var ChannelMutex sync.Mutex

func init() {
	ChannelManager = make(map[string]*Manager)

	Processor = &process.Process{Pid: int32(os.Getpid())}

	go func() {
		ticker := time.NewTicker(time.Second)
		for range ticker.C {
			ChannelMutex.Lock()
			for _, v := range ChannelManager {
				v.handle()
			}
			ChannelMutex.Unlock()
		}
	}()
}

type Manager struct {
	connections   *xsync.MapOf[string, Tracker]
	uploadTemp    atomic.Int64
	downloadTemp  atomic.Int64
	uploadBlip    atomic.Int64
	downloadBlip  atomic.Int64
	uploadTotal   atomic.Int64
	downloadTotal atomic.Int64
}

func NewManager(channelname string) *Manager {
	manager := &Manager{
		connections:   xsync.NewMapOf[string, Tracker](),
		uploadTemp:    atomic.NewInt64(0),
		downloadTemp:  atomic.NewInt64(0),
		uploadBlip:    atomic.NewInt64(0),
		downloadBlip:  atomic.NewInt64(0),
		uploadTotal:   atomic.NewInt64(0),
		downloadTotal: atomic.NewInt64(0),
	}
	ChannelManager[channelname] = manager
	return manager
}

func (m *Manager) Join(c Tracker) {
	m.connections.Store(c.ID(), c)
}

func (m *Manager) Leave(c Tracker) {
	m.connections.Delete(c.ID())
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

func (m *Manager) Snapshot() *Snapshot {
	var connections []*TrackerInfo = make([]*TrackerInfo, 0)
	m.Range(func(c Tracker) bool {
		connections = append(connections, c.Info())
		return true
	})
	return &Snapshot{
		UploadTotal:   m.uploadTotal.Load(),
		DownloadTotal: m.downloadTotal.Load(),
		Connections:   connections,
	}
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
	m.uploadBlip.Store(m.uploadTemp.Load())
	m.uploadTemp.Store(0)
	m.downloadBlip.Store(m.downloadTemp.Load())
	m.downloadTemp.Store(0)
}

type Snapshot struct {
	DownloadTotal int64          `json:"downloadTotal"`
	UploadTotal   int64          `json:"uploadTotal"`
	Connections   []*TrackerInfo `json:"connections"`
	Memory        uint64         `json:"memory"`
}

func Snapshots() map[string]*Snapshot {
	var snapshots map[string]*Snapshot = make(map[string]*Snapshot)
	for k, v := range ChannelManager {
		snapshots[k] = v.Snapshot()
	}
	return snapshots
}

func SaveChannelsData(filename string) {
	snapshots := Snapshots()
	for _, v := range snapshots {
		v.Connections = nil
	}

	if bytes, err := json.Marshal(snapshots); err == nil {
		err = os.WriteFile(filename, bytes, 0666)
		if err != nil {
			log.Errorln(err.Error())
		}

	}
}
func RestoreChannelsData(filename string) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return
	}
	var snapshots = map[string]Snapshot{}
	err = json.Unmarshal(bytes, &snapshots)
	if err != nil {
		log.Errorln(err.Error())
		return
	}
	ChannelMutex.Lock()
	defer ChannelMutex.Unlock()
	for k, v := range snapshots {
		manager := NewManager(k)
		manager.downloadTotal.Add(v.DownloadTotal)
		manager.uploadTotal.Add(v.UploadTotal)
	}
}
