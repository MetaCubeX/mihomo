package sing_tun

import (
	"errors"
	"runtime"
	"sync"

	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/sing-tun"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

type packageManagerCallback struct{}

func (cb *packageManagerCallback) OnPackagesUpdated(packageCount int, sharedCount int) {}

func newPackageManager() (tun.PackageManager, error) {
	packageManager, err := tun.NewPackageManager(tun.PackageManagerOptions{
		Callback: &packageManagerCallback{},
		Logger:   log.SingLogger,
	})
	if err != nil {
		return nil, err
	}
	err = packageManager.Start()
	if err != nil {
		return nil, err
	}
	return packageManager, nil
}

var (
	globalPM tun.PackageManager
	pmOnce   sync.Once
	pmErr    error
)

func getPackageManager() (tun.PackageManager, error) {
	pmOnce.Do(func() {
		globalPM, pmErr = newPackageManager()
	})
	return globalPM, pmErr
}

func (l *Listener) buildAndroidRules(tunOptions *tun.Options) error {
	packageManager, err := getPackageManager()
	if err != nil {
		return err
	}
	tunOptions.BuildAndroidRules(packageManager, l.handler)
	return nil
}

func findPackageName(metadata *constant.Metadata) (string, error) {
	packageManager, err := getPackageManager()
	if err != nil {
		return "", err
	}
	uid := metadata.Uid
	if sharedPackage, loaded := packageManager.SharedPackageByID(uid % 100000); loaded {
		return sharedPackage, nil
	}
	if packageName, loaded := packageManager.PackageByID(uid % 100000); loaded {
		return packageName, nil
	}
	return "", errors.New("package not found")
}

func init() {
	if !features.CMFA {
		process.DefaultPackageNameResolver = findPackageName
	}
}

func (l *Listener) openAndroidHotspot(tunOptions tun.Options) {
	if runtime.GOOS == "android" && tunOptions.AutoRoute {
		priority := 9000
		if len(tunOptions.ExcludedRanges()) > 0 {
			priority++
		}
		if tunOptions.InterfaceMonitor.AndroidVPNEnabled() {
			priority++
		}
		it := netlink.NewRule()
		it.Priority = priority
		it.IifName = tunOptions.Name
		it.Table = 254 //main
		it.Family = unix.AF_INET
		it.SuppressPrefixlen = 0
		err := netlink.RuleAdd(it)
		if err != nil {
			log.Warnln("[TUN] add AndroidHotspot rule error")
		}
	}
}
