//go:build linux

package sing_tun

import (
	"context"
	"os/exec"
	"time"

	"github.com/metacubex/mihomo/log"
)

func configureSystemDNSSearchDomains(ctx context.Context, tunName string, searchDomains []string) {
	args := systemDNSSearchDomainArgs(tunName, searchDomains)
	ctlPath, err := exec.LookPath("resolvectl")
	if err != nil {
		log.Debugln("[TUN] skip dns-search-domains for %s: resolvectl not found", tunName)
		return
	}

	go func() {
		var success bool
		var lastErr error
		for _, delay := range []time.Duration{0, 200 * time.Millisecond, time.Second} {
			if delay > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
			}
			if err := exec.CommandContext(ctx, ctlPath, args...).Run(); err != nil {
				lastErr = err
				continue
			}
			success = true
		}
		if !success && lastErr != nil && ctx.Err() == nil {
			log.Warnln("[TUN] set dns-search-domains for %s failed: %v", tunName, lastErr)
		}
	}()
}
