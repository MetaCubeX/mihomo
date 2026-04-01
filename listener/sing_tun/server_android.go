//go:build android && !cmfa

package sing_tun

import (
	"errors"
	"sync"

	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/sing-tun"
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
