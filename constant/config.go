package constant

import (
	"os"
	"os/user"
	"path"

	log "github.com/sirupsen/logrus"
)

const (
	Name = "clash"
)

var (
	HomeDir    string
	ConfigPath string
	MMDBPath   string
)

type General struct {
	Mode      *string `json:"mode,omitempty"`
	AllowLan  *bool   `json:"allow-lan,omitempty"`
	Port      *int    `json:"port,omitempty"`
	SocksPort *int    `json:"socks-port,omitempty"`
	LogLevel  *string `json:"log-level,omitempty"`
}

func init() {
	currentUser, err := user.Current()
	if err != nil {
		dir := os.Getenv("HOME")
		if dir == "" {
			log.Fatalf("Can't get current user: %s", err.Error())
		}
		HomeDir = dir
	} else {
		HomeDir = currentUser.HomeDir
	}

	dirPath := path.Join(HomeDir, ".config", Name)
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		if err := os.MkdirAll(dirPath, 0777); err != nil {
			log.Fatalf("Can't create config directory %s: %s", dirPath, err.Error())
		}
	}

	ConfigPath = path.Join(dirPath, "config.ini")
	MMDBPath = path.Join(dirPath, "Country.mmdb")
}
