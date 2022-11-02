package sing_tun

import (
	tun "github.com/sagernet/sing-tun"
)

func (l *Listener) buildAndroidRules(tunOptions *tun.Options) error {
	packageManager, err := tun.NewPackageManager(l.handler)
	if err != nil {
		return err
	}
	err = packageManager.Start()
	if err != nil {
		return err
	}
	l.packageManager = packageManager
	tunOptions.BuildAndroidRules(packageManager, l.handler)
	return nil
}

func (h *ListenerHandler) OnPackagesUpdated(packages int, sharedUsers int) {
	return
}
