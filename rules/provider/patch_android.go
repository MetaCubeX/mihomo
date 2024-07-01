//go:build android && cmfa

package provider

import "time"

var (
	suspended bool
)

type UpdatableProvider interface {
	UpdatedAt() time.Time
}

func (rp *ruleSetProvider) UpdatedAt() time.Time {
	return rp.Fetcher.UpdatedAt
}

func (rp *ruleSetProvider) Close() error {
	rp.Fetcher.Destroy()

	return nil
}

func Suspend(s bool) {
	suspended = s
}
