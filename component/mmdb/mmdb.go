package mmdb

import (
	"context"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	clashHttp "github.com/Dreamacro/clash/component/http"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"

	"github.com/oschwald/geoip2-golang"
)

var (
	mmdb *geoip2.Reader
	once sync.Once
)

func LoadFromBytes(buffer []byte) {
	once.Do(func() {
		var err error
		mmdb, err = geoip2.FromBytes(buffer)
		if err != nil {
			log.Fatalln("Can't load mmdb: %s", err.Error())
		}
	})
}

func Verify() bool {
	instance, err := geoip2.Open(C.Path.MMDB())
	if err == nil {
		instance.Close()
	}
	return err == nil
}

func Instance() *geoip2.Reader {
	once.Do(func() {
		var err error
		mmdb, err = geoip2.Open(C.Path.MMDB())
		if err != nil {
			log.Fatalln("Can't load mmdb: %s", err.Error())
		}
	})

	return mmdb
}

func DownloadMMDB(path string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*90)
	defer cancel()
	resp, err := clashHttp.HttpRequest(ctx, C.MmdbUrl, http.MethodGet, http.Header{"User-Agent": {"clash"}}, nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)

	return err
}
