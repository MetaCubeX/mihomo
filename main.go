package main

import (
	"flag"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/hub"
	"github.com/Dreamacro/clash/proxy"
	"github.com/Dreamacro/clash/tunnel"

	log "github.com/sirupsen/logrus"
)

var (
	homedir string
)

func init() {
	flag.StringVar(&homedir, "d", "", "set configuration directory")
	flag.Parse()
}

func main() {
	tunnel.Instance().Run()
	proxy.Instance().Run()
	hub.Run()

	if homedir != "" {
		if !filepath.IsAbs(homedir) {
			currentDir, _ := os.Getwd()
			homedir = filepath.Join(currentDir, homedir)
		}
		C.SetHomeDir(homedir)
	}

	config.Init()
	err := config.Instance().Parse()
	if err != nil {
		log.Fatalf("Parse config error: %s", err.Error())
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
