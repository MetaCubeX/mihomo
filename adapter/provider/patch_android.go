//go:build android && cmfa

package provider

import (
	"time"
)

var (
	suspended bool
)

type UpdatableProvider interface {
	UpdatedAt() time.Time
}

func (pp *proxySetProvider) UpdatedAt() time.Time {
	return pp.Fetcher.UpdatedAt
}

func (pp *proxySetProvider) Close() error {
	pp.healthCheck.close()
	pp.Fetcher.Destroy()

	return nil
}

func (cp *compatibleProvider) Close() error {
	cp.healthCheck.close()

	return nil
}

func Suspend(s bool) {
	suspended = s
}
