package provider

import (
	"bytes"
	"crypto/md5"
	P "github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/log"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

var (
	fileMode os.FileMode = 0666
	dirMode  os.FileMode = 0755
)

type parser = func([]byte) (interface{}, error)

type fetcher struct {
	name      string
	vehicle   P.Vehicle
	updatedAt *time.Time
	ticker    *time.Ticker
	done      chan struct{}
	hash      [16]byte
	parser    parser
	onUpdate  func(interface{}) error
	interval  time.Duration
}

func (f *fetcher) Name() string {
	return f.name
}

func (f *fetcher) VehicleType() P.VehicleType {
	return f.vehicle.Type()
}

func (f *fetcher) Initial() (interface{}, error) {
	var (
		buf         []byte
		hasLocal    bool
		err         error
		forceUpdate bool
	)

	defer func() {
		if f.ticker != nil {
			go f.pullLoop()
		}
	}()

	if stat, fErr := os.Stat(f.vehicle.Path()); fErr == nil {
		buf, err = ioutil.ReadFile(f.vehicle.Path())
		modTime := stat.ModTime()
		f.updatedAt = &modTime
		hasLocal = true
		if f.interval != 0 && modTime.Add(f.interval).Before(time.Now()) {
			forceUpdate = true
			log.Infoln("[Provider] %s not updated for a long time, force refresh", f.Name())
		}
	} else {
		buf, err = f.vehicle.Read()
	}

	if err != nil {
		return nil, err
	}

	var rules interface{}
	if forceUpdate {
		var forceBuf []byte
		if forceBuf, err = f.vehicle.Read(); err == nil {
			if rules, err = f.parser(forceBuf); err == nil {
				hasLocal = false
				buf = forceBuf
			}
		}
	}

	if err != nil || !forceUpdate {
		rules, err = f.parser(buf)
	}

	if err != nil {
		if !hasLocal {
			return nil, err
		}

		buf, err = f.vehicle.Read()
		if err != nil {
			return nil, err
		}

		rules, err = f.parser(buf)
		if err != nil {
			return nil, err
		}

		hasLocal = false
	}

	if f.vehicle.Type() != P.File && !hasLocal {
		if err := safeWrite(f.vehicle.Path(), buf); err != nil {
			return nil, err
		}
	}

	f.hash = md5.Sum(buf)

	return rules, nil
}

func (f *fetcher) Update() (interface{}, bool, error) {
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

	rules, err := f.parser(buf)
	if err != nil {
		return nil, false, err
	}

	if f.vehicle.Type() != P.File {
		if err := safeWrite(f.vehicle.Path(), buf); err != nil {
			return nil, false, err
		}
	}

	f.updatedAt = &now
	f.hash = hash

	return rules, false, nil
}

func (f *fetcher) Destroy() error {
	if f.ticker != nil {
		f.done <- struct{}{}
	}
	return nil
}

func newFetcher(name string, interval time.Duration, vehicle P.Vehicle, parser parser, onUpdate func(interface{}) error) *fetcher {
	var ticker *time.Ticker
	if interval != 0 {
		ticker = time.NewTicker(interval)
	}

	return &fetcher{
		name:     name,
		ticker:   ticker,
		vehicle:  vehicle,
		parser:   parser,
		done:     make(chan struct{}, 1),
		onUpdate: onUpdate,
		interval: interval,
	}
}

func safeWrite(path string, buf []byte) error {
	dir := filepath.Dir(path)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return err
		}
	}

	return ioutil.WriteFile(path, buf, fileMode)
}

func (f *fetcher) pullLoop() {
	for {
		select {
		case <-f.ticker.C:
			same, err := f.update()
			if same || err != nil {
				continue
			}
		case <-f.done:
			f.ticker.Stop()
			return
		}
	}
}

func (f *fetcher) update() (same bool, err error) {
	elm, same, err := f.Update()
	if err != nil {
		log.Warnln("[Provider] %s pull error: %s", f.Name(), err.Error())
		return
	}

	if same {
		log.Debugln("[Provider] %s's rules doesn't change", f.Name())
		return
	}

	log.Infoln("[Provider] %s's rules update", f.Name())
	if f.onUpdate != nil {
		err := f.onUpdate(elm)
		if err != nil {
			log.Infoln("[Provider] %s update failed", f.Name())
		}
	}

	return
}
