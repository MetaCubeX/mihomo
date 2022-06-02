package common

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/Dreamacro/clash/component/geodata"
	"github.com/Dreamacro/clash/component/geodata/router"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"

	_ "github.com/Dreamacro/clash/component/geodata/memconservative"
	_ "github.com/Dreamacro/clash/component/geodata/standard"
)

type GEOSITE struct {
	*Base
	country    string
	adapter    string
	matcher    *router.DomainMatcher
	recodeSize int
}

func (gs *GEOSITE) RuleType() C.RuleType {
	return C.GEOSITE
}

func (gs *GEOSITE) Match(metadata *C.Metadata) bool {
	if metadata.AddrType != C.AtypDomainName {
		return false
	}

	domain := metadata.Host
	return gs.matcher.ApplyDomain(domain)
}

func (gs *GEOSITE) Adapter() string {
	return gs.adapter
}

func (gs *GEOSITE) Payload() string {
	return gs.country
}

func (gs *GEOSITE) GetDomainMatcher() *router.DomainMatcher {
	return gs.matcher
}

func (gs *GEOSITE) GetRecodeSize() int {
	return gs.recodeSize
}

func NewGEOSITE(country string, adapter string) (*GEOSITE, error) {
	if !initFlag {
		if err := initGeoSite(); err != nil {
			log.Errorln("can't initial GeoSite: %s", err)
			return nil, err
		}
		initFlag = true
	}

	matcher, size, err := geodata.LoadGeoSiteMatcher(country)
	if err != nil {
		return nil, fmt.Errorf("load GeoSite data error, %s", err.Error())
	}

	log.Infoln("Start initial GeoSite rule %s => %s, records: %d", country, adapter, size)

	geoSite := &GEOSITE{
		Base:       &Base{},
		country:    country,
		adapter:    adapter,
		matcher:    matcher,
		recodeSize: size,
	}

	return geoSite, nil
}

var _ C.Rule = (*GEOSITE)(nil)

func downloadGeoSite(path string) (err error) {
	resp, err := http.Get(C.GeoSiteUrl)
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

func initGeoSite() error {
	if _, err := os.Stat(C.Path.GeoSite()); os.IsNotExist(err) {
		log.Infoln("Can't find GeoSite.dat, start download")
		if err := downloadGeoSite(C.Path.GeoSite()); err != nil {
			return fmt.Errorf("can't download GeoSite.dat: %s", err.Error())
		}
		log.Infoln("Download GeoSite.dat finish")
	}
	if !initFlag {
		err := geodata.Verify(C.GeositeName)
		if err != nil {
			log.Warnln("GeoSite.dat invalid, remove and download: %s", err)
			if err := os.Remove(C.Path.GeoSite()); err != nil {
				return fmt.Errorf("can't remove invalid GeoSite.dat: %s", err.Error())
			}
			if err := downloadGeoSite(C.Path.GeoSite()); err != nil {
				return fmt.Errorf("can't download GeoSite.dat: %s", err.Error())
			}
		} else {
			initFlag = true
		}
	}
	return nil
}
