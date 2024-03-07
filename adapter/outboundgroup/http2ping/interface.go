package http2ping

import (
	"context"
	"net/url"
	"time"

	"github.com/metacubex/mihomo/constant"
)

type Pinger interface {
	GetProxy() constant.Proxy
	GetSmoothRtt() uint32
	GetStatus() *PingerStatus
	String() string
	Close() error
}

type PingerGroup interface {
	GetConfig() *Config
	GetMinRttProxy(ctx context.Context) constant.Proxy
	SetProxies(proxies []constant.Proxy)
	GetPingersCopy() map[string]Pinger
}

type Config struct {
	Interval    time.Duration
	Tolerance   time.Duration
	HTTP2Server *url.URL
}

type PingerStatus struct {
	Name          string `json:"name"`
	StatusCode    uint32 `json:"status-code"`
	LatestRtt     uint32 `json:"latest-rtt"`
	SRtt          uint32 `json:"srtt"`
	MeanDeviation uint32 `json:"mean-deviation"`
}

type GroupStatus struct {
	Name    string          `json:"name"`
	Proxies []*PingerStatus `json:"proxies"`
}
