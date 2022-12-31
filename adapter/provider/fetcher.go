package provider

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

type parser = func([]byte) (any, error)

type fetcher struct {
	name      string
	vehicle   types.Vehicle
	interval  time.Duration
	updatedAt *time.Time
	ticker    *time.Ticker
	done      chan struct{}
	hash      [16]byte
	parser    parser
	onUpdate  func(any)
}

func (f *fetcher) Name() string {
	return f.name
}

func (f *fetcher) VehicleType() types.VehicleType {
	return f.vehicle.Type()
}

func (f *fetcher) Initial() (any, error) {
	var (
		buf               []byte
		err               error
		isLocal           bool
		immediatelyUpdate bool
	)
	if stat, fErr := os.Stat(f.vehicle.Path()); fErr == nil {
		buf, err = os.ReadFile(f.vehicle.Path())
		modTime := stat.ModTime()
		f.updatedAt = &modTime
		isLocal = true
		immediatelyUpdate = time.Since(modTime) > f.interval
	} else {
		buf, err = f.vehicle.Read()
	}

	if err != nil {
		return nil, err
	}

	proxies, err := f.parser(buf)
	if err != nil {
		if !isLocal {
			return nil, err
		}

		// parse local file error, fallback to remote
		buf, err = f.vehicle.Read()
		if err != nil {
			return nil, err
		}

		proxies, err = f.parser(buf)
		if err != nil {
			return nil, err
		}

		isLocal = false
	}

	if f.vehicle.Type() != types.File && !isLocal {
		if err := safeWrite(f.vehicle.Path(), buf); err != nil {
			return nil, err
		}
	}

	f.hash = md5.Sum(buf)

	// pull proxies automatically
	if f.ticker != nil {
		go f.pullLoop(immediatelyUpdate)
	}

	return proxies, nil
}

func (f *fetcher) Update() (any, bool, error) {
	buf, err := f.vehicle.Read()
	if err != nil {
		return nil, false, err
	}

	now := time.Now()
	hash := md5.Sum(buf)
	if bytes.Equal(f.hash[:], hash[:]) {
		f.updatedAt = &now
		os.Chtimes(f.vehicle.Path(), now, now)
		return nil, true, nil
	}

	proxies, err := f.parser(buf)
	if err != nil {
		return nil, false, err
	}

	if f.vehicle.Type() != types.File {
		if err := safeWrite(f.vehicle.Path(), buf); err != nil {
			return nil, false, err
		}
	}

	f.updatedAt = &now
	f.hash = hash

	return proxies, false, nil
}

func (f *fetcher) Destroy() error {
	if f.ticker != nil {
		f.done <- struct{}{}
	}
	return nil
}

func (f *fetcher) pullLoop(immediately bool) {
	update := func() {
		elm, same, err := f.Update()
		if err != nil {
			log.Warnln("[Provider] %s pull error: %s", f.Name(), err.Error())
			return
		}

		if same {
			log.Debugln("[Provider] %s's proxies doesn't change", f.Name())
			return
		}

		log.Infoln("[Provider] %s's proxies update", f.Name())
		if f.onUpdate != nil {
			f.onUpdate(elm)
		}
	}

	if immediately {
		update()
	}

	for {
		select {
		case <-f.ticker.C:
			update()
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

func newFetcher(name string, interval time.Duration, vehicle types.Vehicle, parser parser, onUpdate func(any)) *fetcher {
	var ticker *time.Ticker
	if interval != 0 {
		ticker = time.NewTicker(interval)
	}

	return &fetcher{
		name:     name,
		ticker:   ticker,
		vehicle:  vehicle,
		interval: interval,
		parser:   parser,
		done:     make(chan struct{}, 1),
		onUpdate: onUpdate,
	}
}
