package provider

import "time"

var (
	suspended bool
)

type UpdatableProvider interface {
	UpdatedAt() time.Time
}

func (f *ruleSetProvider) UpdatedAt() time.Time {
	return f.Fetcher.UpdatedAt
}

func (rp *ruleSetProvider) Close() error {
	rp.Fetcher.Destroy()

	return nil
}

func Suspend(s bool) {
	suspended = s
}
