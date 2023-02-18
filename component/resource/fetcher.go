package resource

import (
	"bytes"
	"crypto/md5"
	"os"
	"path/filepath"
	"time"

	types "github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/log"
)

var (
	fileMode os.FileMode = 0o666
	dirMode  os.FileMode = 0o755
)

type Parser[V any] func([]byte) (V, error)

type Fetcher[V any] struct {
	resourceType string
	name         string
	vehicle      types.Vehicle
	UpdatedAt    *time.Time
	ticker       *time.Ticker
	done         chan struct{}
	hash         [16]byte
	parser       Parser[V]
	interval     time.Duration
	OnUpdate     func(V)
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
		f.UpdatedAt = &modTime
		isLocal = true
		if f.interval != 0 && modTime.Add(f.interval).Before(time.Now()) {
			log.Warnln("[Provider] %s not updated for a long time, force refresh", f.Name())
			forceUpdate = true
		}
	} else {
		buf, err = f.vehicle.Read()
	}

	if err != nil {
		return getZero[V](), err
	}

	var contents V
	if forceUpdate {
		var forceBuf []byte
		if forceBuf, err = f.vehicle.Read(); err == nil {
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
			return getZero[V](), err
		}

		// parse local file error, fallback to remote
		buf, err = f.vehicle.Read()
		if err != nil {
			return getZero[V](), err
		}

		contents, err = f.parser(buf)
		if err != nil {
			return getZero[V](), err
		}

		isLocal = false
	}

	if f.vehicle.Type() != types.File && !isLocal {
		if err := safeWrite(f.vehicle.Path(), buf); err != nil {
			return getZero[V](), err
		}
	}

	f.hash = md5.Sum(buf)

	// pull contents automatically
	if f.ticker != nil {
		go f.pullLoop()
	}

	return contents, nil
}

func (f *Fetcher[V]) Update() (V, bool, error) {
	buf, err := f.vehicle.Read()
	if err != nil {
		return getZero[V](), false, err
	}

	now := time.Now()
	hash := md5.Sum(buf)
	if bytes.Equal(f.hash[:], hash[:]) {
		f.UpdatedAt = &now
		_ = os.Chtimes(f.vehicle.Path(), now, now)
		return getZero[V](), true, nil
	}

	contents, err := f.parser(buf)
	if err != nil {
		return getZero[V](), false, err
	}

	if f.vehicle.Type() != types.File {
		if err := safeWrite(f.vehicle.Path(), buf); err != nil {
			return getZero[V](), false, err
		}
	}

	f.UpdatedAt = &now
	f.hash = hash

	return contents, false, nil
}

func (f *Fetcher[V]) Destroy() error {
	if f.ticker != nil {
		f.done <- struct{}{}
	}
	return nil
}

func (f *Fetcher[V]) pullLoop() {
	for {
		select {
		case <-f.ticker.C:
			elm, same, err := f.Update()
			if err != nil {
				log.Errorln("[Provider] %s pull error: %s", f.Name(), err.Error())
				continue
			}

			if same {
				log.Debugln("[Provider] %s's content doesn't change", f.Name())
				continue
			}

			log.Infoln("[Provider] %s's content update", f.Name())
			if f.OnUpdate != nil {
				f.OnUpdate(elm)
			}
		case <-f.done:
			f.ticker.Stop()
			return
		}
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
	var ticker *time.Ticker
	if interval != 0 {
		ticker = time.NewTicker(interval)
	}

	return &Fetcher[V]{
		name:     name,
		ticker:   ticker,
		vehicle:  vehicle,
		parser:   parser,
		done:     make(chan struct{}, 1),
		OnUpdate: onUpdate,
		interval: interval,
	}
}

func getZero[V any]() V {
	var result V
	return result
}
