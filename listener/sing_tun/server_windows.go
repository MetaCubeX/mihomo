package sing_tun

import (
	"time"

	"github.com/metacubex/mihomo/log"

	tun "github.com/metacubex/sing-tun"

	"golang.org/x/sys/windows"
)

func tunNew(options tun.Options) (tunIf tun.Tun, err error) {
	maxRetry := 3
	for i := 0; i < maxRetry; i++ {
		timeBegin := time.Now()
		tunIf, err = tun.New(options)
		if err == nil {
			return
		}
		timeEnd := time.Now()
		if timeEnd.Sub(timeBegin) < 1*time.Second { // retrying for "Cannot create a file when that file already exists."
			return
		}
		log.Warnln("Start Tun interface timeout: %s [retrying %d/%d]", err, i+1, maxRetry)
	}
	return
}

func init() {
	tun.TunnelType = InterfaceName

	majorVersion, _, _ := windows.RtlGetNtVersionNumbers()
	if majorVersion < 10 {
		// to resolve "bind: The requested address is not valid in its context"
		EnforceBindInterface = true
	}
}
