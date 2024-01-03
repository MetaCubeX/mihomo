package mmdb

import (
	"context"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	mihomoHttp "github.com/metacubex/mihomo/component/http"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/oschwald/maxminddb-golang"
)

type databaseType = uint8

const (
	typeMaxmind databaseType = iota
	typeSing
	typeMetaV0
)

var (
	reader Reader
	once   sync.Once
)

func LoadFromBytes(buffer []byte) {
	once.Do(func() {
		mmdb, err := maxminddb.FromBytes(buffer)
		if err != nil {
			log.Fatalln("Can't load mmdb: %s", err.Error())
		}
		reader = Reader{Reader: mmdb}
		switch mmdb.Metadata.DatabaseType {
		case "sing-geoip":
			reader.databaseType = typeSing
		case "Meta-geoip0":
			reader.databaseType = typeMetaV0
		default:
			reader.databaseType = typeMaxmind
		}
	})
}

func Verify() bool {
	instance, err := maxminddb.Open(C.Path.MMDB())
	if err == nil {
		instance.Close()
	}
	return err == nil
}

func Instance() Reader {
	once.Do(func() {
		mmdbPath := C.Path.MMDB()
		log.Debugln("Load MMDB file: %s", mmdbPath)
		mmdb, err := maxminddb.Open(mmdbPath)
		if err != nil {
			log.Fatalln("Can't load MMDB: %s", err.Error())
		}
		reader = Reader{Reader: mmdb}
		switch mmdb.Metadata.DatabaseType {
		case "sing-geoip":
			reader.databaseType = typeSing
		case "Meta-geoip0":
			reader.databaseType = typeMetaV0
		default:
			reader.databaseType = typeMaxmind
		}
	})

	return reader
}

func DownloadMMDB(path string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*90)
	defer cancel()
	resp, err := mihomoHttp.HttpRequest(ctx, C.MmdbUrl, http.MethodGet, http.Header{"User-Agent": {C.UA}}, nil)
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
