package main

import (
	"flag"
	"fmt"
	"github.com/metacubex/mihomo/component/updater"
	"github.com/metacubex/mihomo/hub"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"

	cs "github.com/metacubex/mihomo/service"
	"go.uber.org/automaxprocs/maxprocs"
)

var (
	version     bool
	testConfig  bool
	geodataMode bool
	//homeDir                string
	//configFile             string
	externalUI             string
	externalController     string
	externalControllerUnix string
	secret                 string

	service string
	flagset map[string]bool
)

func init() {
	//flag.StringVar(&homeDir, "d", os.Getenv("CLASH_HOME_DIR"), "set configuration directory")
	//flag.StringVar(&configFile, "f", os.Getenv("CLASH_CONFIG_FILE"), "specify configuration file")
	flag.StringVar(&externalUI, "ext-ui", os.Getenv("CLASH_OVERRIDE_EXTERNAL_UI_DIR"), "override external ui directory")
	flag.StringVar(&externalController, "ext-ctl", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER"), "override external controller address")
	flag.StringVar(&externalControllerUnix, "ext-ctl-unix", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_UNIX"), "override external controller unix address")
	flag.StringVar(&secret, "secret", os.Getenv("CLASH_OVERRIDE_SECRET"), "override secret for RESTful API")
	flag.BoolVar(&geodataMode, "m", false, "set geodata mode")
	flag.BoolVar(&version, "v", false, "show current version of mihomo")
	flag.BoolVar(&testConfig, "t", false, "test configuration and exit")
	flag.StringVar(&service, "s", "", "Service control action: status, install (as a service), uninstall (as a service), start(in daemon), stop(daemon), restart(stop then start)")
	flag.Parse()

	flagset = map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		flagset[f.Name] = true
	})
}

func main() {
	a := 1
	log.Infoln("ptr size %d", unsafe.Sizeof(&a))
	_, _ = maxprocs.Set(maxprocs.Logger(func(string, ...any) {}))
	if version {
		fmt.Printf("Mihomo Meta %s %s %s with %s %s\n",
			C.Version, runtime.GOOS, runtime.GOARCH, runtime.Version(), C.BuildTime)
		if tags := features.Tags(); len(tags) != 0 {
			fmt.Printf("Use tags: %s\n", strings.Join(tags, ", "))
		}

		return
	}

	if geodataMode {
		C.GeodataMode = true
	}

	if err := config.Init(C.Path.HomeDir()); err != nil {
		log.Fatalln("Initial configuration directory error: %s", err.Error())
	}

	if testConfig {
		if _, err := executor.Parse(); err != nil {
			log.Errorln(err.Error())
			fmt.Printf("configuration file %s test failed\n", C.Path.Config())
			os.Exit(1)
		}
		fmt.Printf("configuration file %s test is successful\n", C.Path.Config())
		return
	}

	prg := cs.NewService(run)
	if flagset["s"] {
		prg.Action(service)
		return
	}
	prg.RunIt()
}

func run() {
	var options []hub.Option
	if externalUI != "" {
		options = append(options, hub.WithExternalUI(externalUI))
	}
	if externalController != "" {
		options = append(options, hub.WithExternalController(externalController))
	}
	if externalControllerUnix != "" {
		options = append(options, hub.WithExternalControllerUnix(externalControllerUnix))
	}
	if secret != "" {
		options = append(options, hub.WithSecret(secret))
	}

	if err := hub.Parse(options...); err != nil {
		log.Fatalln("Parse config error: %s", err.Error())
	}

	if C.GeoAutoUpdate {
		updater.RegisterGeoUpdater(func() {
			cfg, err := executor.ParseWithPath(C.Path.Config())
			if err != nil {
				log.Errorln("[GEO] update GEO databases failed: %v", err)
				return
			}

			log.Warnln("[GEO] update GEO databases success, applying config")

			executor.ApplyConfig(cfg, false)
		})
	}

	defer executor.Shutdown()
	memoryUsage()
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

// memoryUsage implements a couple of not really beautiful hacks which purpose is to
// make OS reclaim the memory freed by AdGuard Home as soon as possible.
func memoryUsage() {
	debug.SetGCPercent(10)

	// madvdontneed: setting madvdontneed=1 will use MADV_DONTNEED
	// instead of MADV_FREE on Linux when returning memory to the
	// kernel. This is less efficient, but causes RSS numbers to drop
	// more quickly.
	_ = os.Setenv("GODEBUG", "madvdontneed=1")

	// periodically call "debug.FreeOSMemory" so
	// that the OS could reclaim the free memory
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		for {
			select {
			case t := <-ticker.C:
				t.Second()
				debug.FreeOSMemory()
			}
		}
	}()
}
