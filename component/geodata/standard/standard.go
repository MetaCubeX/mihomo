package standard

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"

	"google.golang.org/protobuf/proto"
)

func ReadFile(path string) ([]byte, error) {
	reader, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func(reader *os.File) {
		_ = reader.Close()
	}(reader)

	return io.ReadAll(reader)
}

func ReadAsset(file string) ([]byte, error) {
	return ReadFile(C.Path.GetAssetLocation(file))
}

func loadIP(geoipBytes []byte, country string) ([]*router.CIDR, error) {
	var geoipList router.GeoIPList
	if err := proto.Unmarshal(geoipBytes, &geoipList); err != nil {
		return nil, err
	}

	for _, geoip := range geoipList.Entry {
		if strings.EqualFold(geoip.CountryCode, country) {
			return geoip.Cidr, nil
		}
	}

	return nil, fmt.Errorf("country %s not found", country)
}

func loadSite(geositeBytes []byte, list string) ([]*router.Domain, error) {
	var geositeList router.GeoSiteList
	if err := proto.Unmarshal(geositeBytes, &geositeList); err != nil {
		return nil, err
	}

	for _, site := range geositeList.Entry {
		if strings.EqualFold(site.CountryCode, list) {
			return site.Domain, nil
		}
	}

	return nil, fmt.Errorf("list %s not found", list)
}

type standardLoader struct{}

func (d standardLoader) LoadSiteByPath(filename, list string) ([]*router.Domain, error) {
	geositeBytes, err := ReadAsset(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %s, base error: %s", filename, err.Error())
	}
	return loadSite(geositeBytes, list)
}

func (d standardLoader) LoadSiteByBytes(geositeBytes []byte, list string) ([]*router.Domain, error) {
	return loadSite(geositeBytes, list)
}

func (d standardLoader) LoadIPByPath(filename, country string) ([]*router.CIDR, error) {
	geoipBytes, err := ReadAsset(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %s, base error: %s", filename, err.Error())
	}
	return loadIP(geoipBytes, country)
}

func (d standardLoader) LoadIPByBytes(geoipBytes []byte, country string) ([]*router.CIDR, error) {
	return loadIP(geoipBytes, country)
}

func init() {
	geodata.RegisterGeoDataLoaderImplementationCreator("standard", func() geodata.LoaderImplementation {
		return standardLoader{}
	})
}
