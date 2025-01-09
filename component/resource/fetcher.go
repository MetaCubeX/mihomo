package resource

import (
	"context"
	"os"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	types "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"

	"github.com/sagernet/fswatch"
	"github.com/samber/lo"
)

type Parser[V any] func([]byte) (V, error)

type Fetcher[V any] struct {
	ctx          context.Context
	ctxCancel    context.CancelFunc
	resourceType string
	name         string
	vehicle      types.Vehicle
	updatedAt    time.Time
	hash         utils.HashType
	parser       Parser[V]
	interval     time.Duration
	onUpdate     func(V)
	watcher      *fswatch.Watcher
}

func (f *Fetcher[V]) Name() string {
	return f.name
}

func (f *Fetcher[V]) Vehicle() types.Vehicle {
	return f.vehicle
}

func (f *Fetcher[V]) VehicleType() types.VehicleType {
	return f.vehicle.Type()
}

func (f *Fetcher[V]) UpdatedAt() time.Time {
	return f.updatedAt
}

func (f *Fetcher[V]) Initial() (V, error) {
	var (
		buf      []byte
		contents V
		err      error
	)

	if stat, fErr := os.Stat(f.vehicle.Path()); fErr == nil {
		// local file exists, use it first
		buf, err = os.ReadFile(f.vehicle.Path())
		modTime := stat.ModTime()
		contents, _, err = f.loadBuf(buf, utils.MakeHash(buf), false)
		f.updatedAt = modTime // reset updatedAt to file's modTime

		if err == nil {
			err = f.startPullLoop(time.Since(modTime) > f.interval)
			if err != nil {
				return lo.Empty[V](), err
			}
			return contents, nil
		}
	}

	// parse local file error, fallback to remote
	contents, _, err = f.Update()

	if err != nil {
		return lo.Empty[V](), err
	}
	err = f.startPullLoop(false)
	if err != nil {
		return lo.Empty[V](), err
	}
	return contents, nil
}

func (f *Fetcher[V]) Update() (V, bool, error) {
	buf, hash, err := f.vehicle.Read(f.ctx, f.hash)
	if err != nil {
		return lo.Empty[V](), false, err
	}
	return f.loadBuf(buf, hash, f.vehicle.Type() != types.File)
}

func (f *Fetcher[V]) SideUpdate(buf []byte) (V, bool, error) {
	return f.loadBuf(buf, utils.MakeHash(buf), true)
}

func (f *Fetcher[V]) loadBuf(buf []byte, hash utils.HashType, updateFile bool) (V, bool, error) {
	now := time.Now()
	if f.hash.Equal(hash) {
		if updateFile {
			_ = os.Chtimes(f.vehicle.Path(), now, now)
		}
		f.updatedAt = now
		return lo.Empty[V](), true, nil
	}

	if buf == nil { // f.hash has been changed between f.vehicle.Read but should not happen (cause by concurrent)
		return lo.Empty[V](), true, nil
	}

	contents, err := f.parser(buf)
	if err != nil {
		return lo.Empty[V](), false, err
	}

	if updateFile {
		if err = f.vehicle.Write(buf); err != nil {
			return lo.Empty[V](), false, err
		}
	}
	f.updatedAt = now
	f.hash = hash

	if f.onUpdate != nil {
		f.onUpdate(contents)
	}

	return contents, false, nil
}

func (f *Fetcher[V]) Close() error {
	f.ctxCancel()
	if f.watcher != nil {
		_ = f.watcher.Close()
	}
	return nil
}

func (f *Fetcher[V]) pullLoop(forceUpdate bool) {
	initialInterval := f.interval - time.Since(f.updatedAt)
	if initialInterval > f.interval {
		initialInterval = f.interval
	}

	if forceUpdate {
		log.Warnln("[Provider] %s not updated for a long time, force refresh", f.Name())
		f.updateWithLog()
	}

	timer := time.NewTimer(initialInterval)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			timer.Reset(f.interval)
			f.updateWithLog()
		case <-f.ctx.Done():
			return
		}
	}
}

func (f *Fetcher[V]) startPullLoop(forceUpdate bool) (err error) {
	// pull contents automatically
	if f.vehicle.Type() == types.File {
		f.watcher, err = fswatch.NewWatcher(fswatch.Options{
			Path:     []string{f.vehicle.Path()},
			Direct:   true,
			Callback: f.updateCallback,
		})
		if err != nil {
			return err
		}
		err = f.watcher.Start()
		if err != nil {
			return err
		}
	} else if f.interval > 0 {
		go f.pullLoop(forceUpdate)
	}
	return
}

func (f *Fetcher[V]) updateCallback(path string) {
	f.updateWithLog()
}

func (f *Fetcher[V]) updateWithLog() {
	_, same, err := f.Update()
	if err != nil {
		log.Errorln("[Provider] %s pull error: %s", f.Name(), err.Error())
		return
	}

	if same {
		log.Debugln("[Provider] %s's content doesn't change", f.Name())
		return
	}

	log.Infoln("[Provider] %s's content update", f.Name())
	return
}

func NewFetcher[V any](name string, interval time.Duration, vehicle types.Vehicle, parser Parser[V], onUpdate func(V)) *Fetcher[V] {
	ctx, cancel := context.WithCancel(context.Background())
	return &Fetcher[V]{
		ctx:       ctx,
		ctxCancel: cancel,
		name:      name,
		vehicle:   vehicle,
		parser:    parser,
		onUpdate:  onUpdate,
		interval:  interval,
	}
}
