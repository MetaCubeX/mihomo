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
	String() string
	Close() error
}

type PingerGroup interface {
	GetMinRttProxy(ctx context.Context) constant.Proxy
	SetProxies(proxies []constant.Proxy)
}

type Config struct {
	Interval    time.Duration
	Tolerance   time.Duration
	HTTP2Server *url.URL
}
