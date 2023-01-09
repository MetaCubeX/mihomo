package config

import (
	"fmt"
	"github.com/Dreamacro/clash/component/geodata"
	"os"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

// Init prepare necessary files
func Init(dir string) error {
	// initial homedir
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o777); err != nil {
			return fmt.Errorf("can't create config directory %s: %s", dir, err.Error())
		}
	}

	// initial config.yaml
	if _, err := os.Stat(C.Path.Config()); os.IsNotExist(err) {
		log.Infoln("Can't find config, create a initial config file")
		f, err := os.OpenFile(C.Path.Config(), os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("can't create file %s: %s", C.Path.Config(), err.Error())
		}
		f.Write([]byte(`mixed-port: 7890`))
		f.Close()
	}
	buf, _ := os.ReadFile(C.Path.Config())
	rawCfg, err := UnmarshalRawConfig(buf)
	if err != nil {
		log.Errorln(err.Error())
		fmt.Printf("configuration file %s test failed\n", C.Path.Config())
		os.Exit(1)
	}
	if !C.GeodataMode {
		C.GeodataMode = rawCfg.GeodataMode
	}
	C.GeoIpUrl = rawCfg.GeoXUrl.GeoIp
	C.GeoSiteUrl = rawCfg.GeoXUrl.GeoSite
	C.MmdbUrl = rawCfg.GeoXUrl.Mmdb
	// initial GeoIP
	if err := geodata.InitGeoIP(); err != nil {
		return fmt.Errorf("can't initial GeoIP: %w", err)
	}

	return nil
}
