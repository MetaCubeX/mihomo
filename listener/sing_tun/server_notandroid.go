//go:build !android || cmfa

package sing_tun

import (
	tun "github.com/metacubex/sing-tun"
)

func (l *Listener) buildAndroidRules(tunOptions *tun.Options) error {
	return nil
}
