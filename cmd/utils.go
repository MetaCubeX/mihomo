package cmd

import (
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/cmd/flags"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
	"go.uber.org/automaxprocs/maxprocs"
)

var (
	updateGeoMux sync.Mutex
	updatingGeo  = false
)

func setupMaxProcs() {
	_, _ = maxprocs.Set(maxprocs.Logger(func(string, ...any) {}))
}

func resolvePath(path string) string {
	if !filepath.IsAbs(path) {
		currentDir, _ := os.Getwd()
		return filepath.Join(currentDir, path)
	}
	return path
}

func parseOptions() []hub.Option {
	var options []hub.Option
	if flags.ExternalUI != "" {
		options = append(options, hub.WithExternalUI(flags.ExternalUI))
	}
	if flags.ExternalController != "" {
		options = append(options, hub.WithExternalController(flags.ExternalController))
	}
	if flags.Secret != "" {
		options = append(options, hub.WithSecret(flags.Secret))
	}
	return options
}

func updateGeoDatabases() {
	log.Infoln("[GEO] Start updating GEO database")
	updateGeoMux.Lock()

	if updatingGeo {
		updateGeoMux.Unlock()
		log.Infoln("[GEO] GEO database is updating, skip")
		return
	}

	updatingGeo = true
	updateGeoMux.Unlock()

	go func() {
		defer func() {
			updatingGeo = false
		}()

		log.Infoln("[GEO] Updating GEO database")

		if err := config.UpdateGeoDatabases(); err != nil {
			log.Errorln("[GEO] update GEO database error: %s", err.Error())
			return
		}

		cfg, err := executor.ParseWithPath(C.Path.Config())
		if err != nil {
			log.Errorln("[GEO] update GEO database failed: %s", err.Error())
			return
		}

		log.Infoln("[GEO] Update GEO database success, apply new config")
		executor.ApplyConfig(cfg, false)
	}()
}

func startGeoUpdater() {
	ticker := time.NewTicker(time.Duration(C.GeoUpdateInterval) * time.Hour)

	log.Infoln("[GEO] Start update GEO database every %d hours", C.GeoUpdateInterval)
	go func() {
		for range ticker.C {
			updateGeoDatabases()
		}
	}()
}

func handleSignals() {
	termSign := make(chan os.Signal, 1)
	hupSign := make(chan os.Signal, 1)
	signal.Notify(termSign, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(hupSign, syscall.SIGHUP)
	for {
		select {
		case <-termSign:
			return
		case <-hupSign:
			if cfg, err := executor.ParseWithPath(C.Path.Config()); err == nil {
				executor.ApplyConfig(cfg, true)
			} else {
				log.Errorln("Parse config error: %s", err.Error())
			}
		}
	}
}
