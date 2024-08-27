package resource

import (
	"bytes"
	"context"
	"crypto/md5"
	"os"
	"path/filepath"
	"time"

	types "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"

	"github.com/sagernet/fswatch"
	"github.com/samber/lo"
)

var (
	fileMode os.FileMode = 0o666
	dirMode  os.FileMode = 0o755
)

type Parser[V any] func([]byte) (V, error)

type Fetcher[V any] struct {
	ctx          context.Context
	ctxCancel    context.CancelFunc
	resourceType string
	name         string
	vehicle      types.Vehicle
	updatedAt    time.Time
	hash         [16]byte
	parser       Parser[V]
	interval     time.Duration
	OnUpdate     func(V)
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
		buf         []byte
		err         error
		isLocal     bool
		forceUpdate bool
	)

	if stat, fErr := os.Stat(f.vehicle.Path()); fErr == nil {
		buf, err = os.ReadFile(f.vehicle.Path())
		modTime := stat.ModTime()
		f.updatedAt = modTime
		isLocal = true
		if f.interval != 0 && modTime.Add(f.interval).Before(time.Now()) {
			log.Warnln("[Provider] %s not updated for a long time, force refresh", f.Name())
			forceUpdate = true
		}
	} else {
		buf, err = f.vehicle.Read(f.ctx)
		f.updatedAt = time.Now()
	}

	if err != nil {
		return lo.Empty[V](), err
	}

	var contents V
	if forceUpdate {
		var forceBuf []byte
		if forceBuf, err = f.vehicle.Read(f.ctx); err == nil {
			if contents, err = f.parser(forceBuf); err == nil {
				isLocal = false
				buf = forceBuf
			}
		}
	}

	if err != nil || !forceUpdate {
		contents, err = f.parser(buf)
	}

	if err != nil {
		if !isLocal {
			return lo.Empty[V](), err
		}

		// parse local file error, fallback to remote
		buf, err = f.vehicle.Read(f.ctx)
		if err != nil {
			return lo.Empty[V](), err
		}

		contents, err = f.parser(buf)
		if err != nil {
			return lo.Empty[V](), err
		}

		isLocal = false
	}

	if f.vehicle.Type() != types.File && !isLocal {
		if err := safeWrite(f.vehicle.Path(), buf); err != nil {
			return lo.Empty[V](), err
		}
	}

	f.hash = md5.Sum(buf)

	// pull contents automatically
	if f.vehicle.Type() == types.File {
		f.watcher, err = fswatch.NewWatcher(fswatch.Options{
			Path:     []string{f.vehicle.Path()},
			Direct:   true,
			Callback: f.update,
		})
		if err != nil {
			return lo.Empty[V](), err
		}
		err = f.watcher.Start()
		if err != nil {
			return lo.Empty[V](), err
		}
	} else if f.interval > 0 {
		go f.pullLoop()
	}

	return contents, nil
}

func (f *Fetcher[V]) Update() (V, bool, error) {
	buf, err := f.vehicle.Read(f.ctx)
	if err != nil {
		return lo.Empty[V](), false, err
	}
	return f.SideUpdate(buf)
}

func (f *Fetcher[V]) SideUpdate(buf []byte) (V, bool, error) {
	now := time.Now()
	hash := md5.Sum(buf)
	if bytes.Equal(f.hash[:], hash[:]) {
		f.updatedAt = now
		_ = os.Chtimes(f.vehicle.Path(), now, now)
		return lo.Empty[V](), true, nil
	}

	contents, err := f.parser(buf)
	if err != nil {
		return lo.Empty[V](), false, err
	}

	if f.vehicle.Type() != types.File {
		if err := safeWrite(f.vehicle.Path(), buf); err != nil {
			return lo.Empty[V](), false, err
		}
	}

	f.updatedAt = now
	f.hash = hash

	return contents, false, nil
}

func (f *Fetcher[V]) Close() error {
	f.ctxCancel()
	if f.watcher != nil {
		_ = f.watcher.Close()
	}
	return nil
}

func (f *Fetcher[V]) pullLoop() {
	initialInterval := f.interval - time.Since(f.updatedAt)
	if initialInterval > f.interval {
		initialInterval = f.interval
	}

	timer := time.NewTimer(initialInterval)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			timer.Reset(f.interval)
			f.update(f.vehicle.Path())
		case <-f.ctx.Done():
			return
		}
	}
}

func (f *Fetcher[V]) update(path string) {
	elm, same, err := f.Update()
	if err != nil {
		log.Errorln("[Provider] %s pull error: %s", f.Name(), err.Error())
		return
	}

	if same {
		log.Debugln("[Provider] %s's content doesn't change", f.Name())
		return
	}

	log.Infoln("[Provider] %s's content update", f.Name())
	if f.OnUpdate != nil {
		f.OnUpdate(elm)
	}
}

func safeWrite(path string, buf []byte) error {
	dir := filepath.Dir(path)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return err
		}
	}

	return os.WriteFile(path, buf, fileMode)
}

func NewFetcher[V any](name string, interval time.Duration, vehicle types.Vehicle, parser Parser[V], onUpdate func(V)) *Fetcher[V] {
	ctx, cancel := context.WithCancel(context.Background())
	return &Fetcher[V]{
		ctx:       ctx,
		ctxCancel: cancel,
		name:      name,
		vehicle:   vehicle,
		parser:    parser,
		OnUpdate:  onUpdate,
		interval:  interval,
	}
}
