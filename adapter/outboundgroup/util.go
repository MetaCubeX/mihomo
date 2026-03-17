package outboundgroup

import (
	"context"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type ProxyGroup interface {
	C.ProxyAdapter

	Providers() []P.ProxyProvider
	Proxies() []C.Proxy
	Now() string
	Touch()

	URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (mp map[string]uint16, err error)
}

var _ ProxyGroup = (*Fallback)(nil)
var _ ProxyGroup = (*LoadBalance)(nil)
var _ ProxyGroup = (*URLTest)(nil)
var _ ProxyGroup = (*Selector)(nil)

type SelectAble interface {
	Set(string) error
	ForceSet(name string)
}

var _ SelectAble = (*Fallback)(nil)
var _ SelectAble = (*URLTest)(nil)
var _ SelectAble = (*Selector)(nil)

type PersistentPinAware interface {
	PersistentPin() bool
}

func latestProxyTestTime(proxy C.Proxy, testURL string) (time.Time, bool) {
	history, ok := proxyTestHistory(proxy, testURL)
	if !ok || len(history) == 0 {
		return time.Time{}, false
	}

	return history[len(history)-1].Time, true
}

func proxyTestHistory(proxy C.Proxy, testURL string) ([]C.DelayHistory, bool) {
	extra := proxy.ExtraDelayHistories()
	state, ok := extra[testURL]
	if !ok || len(state.History) == 0 {
		return nil, false
	}

	return state.History, true
}
