package cachefile

import (
	"bytes"
	"encoding/gob"
	"io/ioutil"
	"os"
	"sync"

	"github.com/Dreamacro/clash/component/profile"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

var (
	initOnce     sync.Once
	fileMode     os.FileMode = 0666
	defaultCache *CacheFile
)

type cache struct {
	Selected map[string]string
}

// CacheFile store and update the cache file
type CacheFile struct {
	path  string
	model *cache
	enc   *gob.Encoder
	buf   *bytes.Buffer
	mux   sync.Mutex
}

func (c *CacheFile) SetSelected(group, selected string) {
	if !profile.StoreSelected.Load() {
		return
	}

	c.mux.Lock()
	defer c.mux.Unlock()

	model, err := c.element()
	if err != nil {
		log.Warnln("[CacheFile] read cache %s failed: %s", c.path, err.Error())
		return
	}

	model.Selected[group] = selected
	c.buf.Reset()
	if err := c.enc.Encode(model); err != nil {
		log.Warnln("[CacheFile] encode gob failed: %s", err.Error())
		return
	}

	if err := ioutil.WriteFile(c.path, c.buf.Bytes(), fileMode); err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.path, err.Error())
		return
	}
}

func (c *CacheFile) SelectedMap() map[string]string {
	if !profile.StoreSelected.Load() {
		return nil
	}

	c.mux.Lock()
	defer c.mux.Unlock()

	model, err := c.element()
	if err != nil {
		log.Warnln("[CacheFile] read cache %s failed: %s", c.path, err.Error())
		return nil
	}

	mapping := map[string]string{}
	for k, v := range model.Selected {
		mapping[k] = v
	}
	return mapping
}

func (c *CacheFile) element() (*cache, error) {
	if c.model != nil {
		return c.model, nil
	}

	model := &cache{
		Selected: map[string]string{},
	}

	if buf, err := ioutil.ReadFile(c.path); err == nil {
		bufReader := bytes.NewBuffer(buf)
		dec := gob.NewDecoder(bufReader)
		if err := dec.Decode(model); err != nil {
			return nil, err
		}
	}

	c.model = model
	return c.model, nil
}

// Cache return singleton of CacheFile
func Cache() *CacheFile {
	initOnce.Do(func() {
		buf := &bytes.Buffer{}
		defaultCache = &CacheFile{
			path: C.Path.Cache(),
			buf:  buf,
			enc:  gob.NewEncoder(buf),
		}
	})

	return defaultCache
}
