package constant

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	P "path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/constant/features"
)

const Name = "mihomo"

var (
	GeositeName = "GeoSite.dat"
	GeoipName   = "GeoIP.dat"
	ASNName     = "ASN.mmdb"
)

// Path is used to get the configuration path
//
// on Unix systems, `$HOME/.config/mihomo`.
// on Windows, `%USERPROFILE%/.config/mihomo`.
var Path = func() *path {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir, _ = os.Getwd()
	}
	allowUnsafePath, _ := strconv.ParseBool(os.Getenv("SKIP_SAFE_PATH_CHECK"))
	homeDir = P.Join(homeDir, ".config", Name)

	if _, err = os.Stat(homeDir); err != nil {
		if configHome, ok := os.LookupEnv("XDG_CONFIG_HOME"); ok {
			homeDir = P.Join(configHome, Name)
		}
	}

	return &path{homeDir: homeDir, configFile: "config.yaml", allowUnsafePath: allowUnsafePath}
}()

type path struct {
	homeDir         string
	configFile      string
	allowUnsafePath bool
}

// SetHomeDir is used to set the configuration path
func SetHomeDir(root string) {
	Path.homeDir = root
}

// SetConfig is used to set the configuration file
func SetConfig(file string) {
	Path.configFile = file
}

func (p *path) HomeDir() string {
	return p.homeDir
}

func (p *path) Config() string {
	return p.configFile
}

// Resolve return a absolute path or a relative path with homedir
func (p *path) Resolve(path string) string {
	if !filepath.IsAbs(path) {
		return filepath.Join(p.HomeDir(), path)
	}
	return path
}

// IsSafePath return true if path is a subpath of homedir
func (p *path) IsSafePath(path string) bool {
	if p.allowUnsafePath || features.CMFA {
		return true
	}
	homedir := p.HomeDir()
	path = p.Resolve(path)
	rel, err := filepath.Rel(homedir, path)
	if err != nil {
		return false
	}

	return !strings.Contains(rel, "..")
}

func (p *path) GetPathByHash(prefix, name string) string {
	hash := md5.Sum([]byte(name))
	filename := hex.EncodeToString(hash[:])
	return filepath.Join(p.HomeDir(), prefix, filename)
}

func (p *path) MMDB() string {
	files, err := os.ReadDir(p.homeDir)
	if err != nil {
		return ""
	}
	for _, fi := range files {
		if fi.IsDir() {
			// 目录则直接跳过
			continue
		} else {
			if strings.EqualFold(fi.Name(), "Country.mmdb") ||
				strings.EqualFold(fi.Name(), "geoip.db") ||
				strings.EqualFold(fi.Name(), "geoip.metadb") {
				GeoipName = fi.Name()
				return P.Join(p.homeDir, fi.Name())
			}
		}
	}
	return P.Join(p.homeDir, "geoip.metadb")
}

func (p *path) ASN() string {
	files, err := os.ReadDir(p.homeDir)
	if err != nil {
		return ""
	}
	for _, fi := range files {
		if fi.IsDir() {
			// 目录则直接跳过
			continue
		} else {
			if strings.EqualFold(fi.Name(), "ASN.mmdb") {
				ASNName = fi.Name()
				return P.Join(p.homeDir, fi.Name())
			}
		}
	}
	return P.Join(p.homeDir, ASNName)
}

func (p *path) OldCache() string {
	return P.Join(p.homeDir, ".cache")
}

func (p *path) Cache() string {
	return P.Join(p.homeDir, "cache.db")
}

func (p *path) GeoIP() string {
	files, err := os.ReadDir(p.homeDir)
	if err != nil {
		return ""
	}
	for _, fi := range files {
		if fi.IsDir() {
			// 目录则直接跳过
			continue
		} else {
			if strings.EqualFold(fi.Name(), "GeoIP.dat") {
				GeoipName = fi.Name()
				return P.Join(p.homeDir, fi.Name())
			}
		}
	}
	return P.Join(p.homeDir, "GeoIP.dat")
}

func (p *path) GeoSite() string {
	files, err := os.ReadDir(p.homeDir)
	if err != nil {
		return ""
	}
	for _, fi := range files {
		if fi.IsDir() {
			// 目录则直接跳过
			continue
		} else {
			if strings.EqualFold(fi.Name(), "GeoSite.dat") {
				GeositeName = fi.Name()
				return P.Join(p.homeDir, fi.Name())
			}
		}
	}
	return P.Join(p.homeDir, "GeoSite.dat")
}

func (p *path) GetAssetLocation(file string) string {
	return P.Join(p.homeDir, file)
}

func (p *path) GetExecutableFullPath() string {
	exePath, err := os.Executable()
	if err != nil {
		return "mihomo"
	}
	res, _ := filepath.EvalSymlinks(exePath)
	return res
}
