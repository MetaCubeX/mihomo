package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/queue"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/puzpuzpuz/xsync/v3"
)

var UnifiedDelay = atomic.NewBool(false)

const (
	defaultHistoriesNum = 10
)

type extraProxyState struct {
	history *queue.Queue[C.DelayHistory]
	alive   atomic.Bool
}

type Proxy struct {
	C.ProxyAdapter
	history *queue.Queue[C.DelayHistory]
	alive   atomic.Bool
	url     string
	extra   *xsync.MapOf[string, *extraProxyState]
}

// AliveForTestUrl implements C.Proxy
func (p *Proxy) AliveForTestUrl(url string) bool {
	if state, ok := p.extra.Load(url); ok {
		return state.alive.Load()
	}

	return p.alive.Load()
}

// Dial implements C.Proxy
func (p *Proxy) Dial(metadata *C.Metadata) (C.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
	defer cancel()
	return p.DialContext(ctx, metadata)
}

// DialContext implements C.ProxyAdapter
func (p *Proxy) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	conn, err := p.ProxyAdapter.DialContext(ctx, metadata, opts...)
	return conn, err
}

// DialUDP implements C.ProxyAdapter
func (p *Proxy) DialUDP(metadata *C.Metadata) (C.PacketConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
	defer cancel()
	return p.ListenPacketContext(ctx, metadata)
}

// ListenPacketContext implements C.ProxyAdapter
func (p *Proxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	pc, err := p.ProxyAdapter.ListenPacketContext(ctx, metadata, opts...)
	return pc, err
}

// DelayHistory implements C.Proxy
func (p *Proxy) DelayHistory() []C.DelayHistory {
	queueM := p.history.Copy()
	histories := []C.DelayHistory{}
	for _, item := range queueM {
		histories = append(histories, item)
	}

	return histories
}

// DelayHistoryForTestUrl implements C.Proxy
func (p *Proxy) DelayHistoryForTestUrl(url string) []C.DelayHistory {
	var queueM []C.DelayHistory

	if state, ok := p.extra.Load(url); ok {
		queueM = state.history.Copy()
	}

	if queueM == nil {
		queueM = p.history.Copy()
	}

	histories := []C.DelayHistory{}
	for _, item := range queueM {
		histories = append(histories, item)
	}
	return histories
}

func (p *Proxy) ExtraDelayHistory() map[string][]C.DelayHistory {
	extraHistory := map[string][]C.DelayHistory{}

	p.extra.Range(func(k string, v *extraProxyState) bool {

		testUrl := k
		state := v

		histories := []C.DelayHistory{}
		queueM := state.history.Copy()

		for _, item := range queueM {
			histories = append(histories, item)
		}

		extraHistory[testUrl] = histories

		return true
	})
	return extraHistory
}

// LastDelay return last history record. if proxy is not alive, return the max value of uint16.
// implements C.Proxy
func (p *Proxy) LastDelay() (delay uint16) {
	var max uint16 = 0xffff
	if !p.alive.Load() {
		return max
	}

	history := p.history.Last()
	if history.Delay == 0 {
		return max
	}
	return history.Delay
}

// LastDelayForTestUrl implements C.Proxy
func (p *Proxy) LastDelayForTestUrl(url string) (delay uint16) {
	var max uint16 = 0xffff

	alive := p.alive.Load()
	history := p.history.Last()

	if state, ok := p.extra.Load(url); ok {
		alive = state.alive.Load()
		history = state.history.Last()
	}

	if !alive {
		return max
	}

	if history.Delay == 0 {
		return max
	}
	return history.Delay
}

// MarshalJSON implements C.ProxyAdapter
func (p *Proxy) MarshalJSON() ([]byte, error) {
	inner, err := p.ProxyAdapter.MarshalJSON()
	if err != nil {
		return inner, err
	}

	mapping := map[string]any{}
	_ = json.Unmarshal(inner, &mapping)
	mapping["history"] = p.DelayHistory()
	mapping["extra"] = p.ExtraDelayHistory()
	mapping["alive"] = p.AliveForTestUrl(p.url)
	mapping["name"] = p.Name()
	mapping["udp"] = p.SupportUDP()
	mapping["xudp"] = p.SupportXUDP()
	mapping["tfo"] = p.SupportTFO()
	return json.Marshal(mapping)
}

// URLTest get the delay for the specified URL
// implements C.Proxy
func (p *Proxy) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (t uint16, err error) {
	defer func() {
		alive := err == nil

		if len(p.url) == 0 || url == p.url {
			p.alive.Store(alive)
			record := C.DelayHistory{Time: time.Now()}
			if alive {
				record.Delay = t
			}
			p.history.Put(record)
			if p.history.Len() > defaultHistoriesNum {
				p.history.Pop()
			}

			// test URL configured by the proxy provider
			if len(p.url) == 0 {
				p.url = url
			}
		} else {
			record := C.DelayHistory{Time: time.Now()}
			if alive {
				record.Delay = t
			}

			state, ok := p.extra.Load(url)
			if !ok {
				state = &extraProxyState{
					history: queue.New[C.DelayHistory](defaultHistoriesNum),
					alive:   atomic.NewBool(true),
				}
				p.extra.Store(url, state)
			}

			state.alive.Store(alive)
			state.history.Put(record)
			if state.history.Len() > defaultHistoriesNum {
				state.history.Pop()
			}
		}
	}()

	unifiedDelay := UnifiedDelay.Load()

	addr, err := urlToMetadata(url)
	if err != nil {
		return
	}

	start := time.Now()
	instance, err := p.DialContext(ctx, &addr)
	if err != nil {
		return
	}
	defer func() {
		_ = instance.Close()
	}()

	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return
	}
	req = req.WithContext(ctx)

	transport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return instance, nil
		},
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	defer client.CloseIdleConnections()

	resp, err := client.Do(req)

	if err != nil {
		return
	}

	_ = resp.Body.Close()

	if unifiedDelay {
		second := time.Now()
		resp, err = client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			start = second
		}
	}

	if expectedStatus != nil && !expectedStatus.Check(uint16(resp.StatusCode)) {
		// maybe another value should be returned for differentiation
		err = errors.New("response status is inconsistent with the expected status")
	}

	t = uint16(time.Since(start) / time.Millisecond)
	return
}

func NewProxy(adapter C.ProxyAdapter) *Proxy {
	return &Proxy{
		ProxyAdapter: adapter,
		history:      queue.New[C.DelayHistory](defaultHistoriesNum),
		alive:        atomic.NewBool(true),
		url:          "",
		extra:        xsync.NewMapOf[string, *extraProxyState]()}
}

func urlToMetadata(rawURL string) (addr C.Metadata, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			err = fmt.Errorf("%s scheme not Support", rawURL)
			return
		}
	}
	uintPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return
	}

	addr = C.Metadata{
		Host:    u.Hostname(),
		DstIP:   netip.Addr{},
		DstPort: uint16(uintPort),
	}
	return
}
