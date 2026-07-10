//go:build !linux

package sing_tun

import "context"

func configureSystemDNSSearchDomains(ctx context.Context, tunName string, searchDomains []string) {}
