package statistic

import (
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/xsync"
	C "github.com/metacubex/mihomo/constant"
)

const (
	minSpeedWindow = time.Second
)

type trackerSample struct {
	mu          sync.Mutex
	leaf        string
	lastTotal   uint64
	windowBytes uint64
	windowStart time.Time
	closed      bool
	tracker     Tracker
}

type SpeedObserver struct {
	trackers  xsync.Map[string, *trackerSample]
	leaveTemp xsync.Map[string, *atomic.Uint64]
}

func NewSpeedObserver() *SpeedObserver {
	return &SpeedObserver{
		trackers:  xsync.Map[string, *trackerSample]{},
		leaveTemp: xsync.Map[string, *atomic.Uint64]{},
	}
}

func (o *SpeedObserver) Join(tt Tracker) {
	info := tt.Info()
	if info == nil || len(info.Chain) == 0 {
		return
	}
	now := time.Now()
	o.trackers.Store(tt.ID(), &trackerSample{
		leaf:        info.Chain[0],
		lastTotal:   uint64(info.DownloadTotal.Load()),
		windowStart: now,
		tracker:     tt,
	})
}

func (o *SpeedObserver) Leave(tt Tracker) {
	s, ok := o.trackers.LoadAndDelete(tt.ID())
	if !ok {
		return
	}
	info := tt.Info()
	if info == nil {
		return
	}
	total := uint64(info.DownloadTotal.Load())
	if leaf, speed, emit := s.flush(time.Now(), total, true); emit {
		slot, _ := o.leaveTemp.LoadOrStoreFn(leaf, func() *atomic.Uint64 {
			return &atomic.Uint64{}
		})
		slot.Add(speed)
	}
}

func (o *SpeedObserver) Tick(now time.Time, resolve func(string) C.Proxy) {
	perProxy := make(map[string]uint64)

	o.trackers.Range(func(_ string, s *trackerSample) bool {
		info := s.tracker.Info()
		if info == nil {
			return true
		}
		total := uint64(info.DownloadTotal.Load())
		if leaf, speed, emit := s.flush(now, total, false); emit {
			perProxy[leaf] += speed
		}
		return true
	})

	o.leaveTemp.Range(func(leaf string, slot *atomic.Uint64) bool {
		if v := slot.Swap(0); v > 0 {
			perProxy[leaf] += v
		}
		return true
	})

	for leaf, speed := range perProxy {
		if p := resolve(leaf); p != nil {
			p.PushSpeed(speed)
		}
	}
}

func (s *trackerSample) flush(now time.Time, total uint64, final bool) (string, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return "", 0, false
	}

	delta := total - s.lastTotal
	s.lastTotal = total
	s.windowBytes += delta

	elapsed := now.Sub(s.windowStart)
	if !final && elapsed < minSpeedWindow {
		return "", 0, false
	}

	if s.windowBytes == 0 {
		if !final {
			s.windowStart = now
		}
		s.closed = final
		return "", 0, false
	}

	denom := elapsed
	if final && denom < minSpeedWindow {
		denom = minSpeedWindow
	}

	speed := uint64(float64(s.windowBytes) / denom.Seconds())
	s.windowBytes = 0
	s.windowStart = now
	s.closed = final
	return s.leaf, speed, true
}
