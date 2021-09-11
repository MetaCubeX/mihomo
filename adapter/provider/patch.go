package provider

import "time"

var (
	suspended bool
)

type UpdatableProvider interface {
	UpdatedAt() time.Time
}

func (f *fetcher) UpdatedAt() time.Time {
	return f.updatedAt
}

func (pp *proxySetProvider) Close() error {
	pp.healthCheck.close()
	pp.fetcher.Destroy()

	return nil
}

func (cp *compatibleProvider) Close() error {
	cp.healthCheck.close()

	return nil
}

func Suspend(s bool) {
	suspended = s
}
