package adapters

import (
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	C "github.com/Dreamacro/clash/constant"
)

type proxy struct {
	RawProxy C.Proxy
	Valid    bool
}

type Fallback struct {
	*Base
	proxies  []*proxy
	rawURL   string
	interval time.Duration
	done     chan struct{}
}

type FallbackOption struct {
	Name     string   `proxy:"name"`
	Proxies  []string `proxy:"proxies"`
	URL      string   `proxy:"url"`
	Interval int      `proxy:"interval"`
}

func (f *Fallback) Now() string {
	_, proxy := f.findNextValidProxy(0)
	if proxy != nil {
		return proxy.RawProxy.Name()
	}
	return f.proxies[0].RawProxy.Name()
}

func (f *Fallback) Generator(metadata *C.Metadata) (net.Conn, error) {
	idx := 0
	var proxy *proxy
	for {
		idx, proxy = f.findNextValidProxy(idx)
		if proxy == nil {
			break
		}
		adapter, err := proxy.RawProxy.Generator(metadata)
		if err != nil {
			proxy.Valid = false
			idx++
			continue
		}
		return adapter, err
	}
	return f.proxies[0].RawProxy.Generator(metadata)
}

func (f *Fallback) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range f.proxies {
		all = append(all, proxy.RawProxy.Name())
	}
	return json.Marshal(map[string]interface{}{
		"type": f.Type().String(),
		"now":  f.Now(),
		"all":  all,
	})
}

func (f *Fallback) Close() {
	f.done <- struct{}{}
}

func (f *Fallback) loop() {
	tick := time.NewTicker(f.interval)
	go f.validTest()
Loop:
	for {
		select {
		case <-tick.C:
			go f.validTest()
		case <-f.done:
			break Loop
		}
	}
}

func (f *Fallback) findNextValidProxy(start int) (int, *proxy) {
	for i := start; i < len(f.proxies); i++ {
		if f.proxies[i].Valid {
			return i, f.proxies[i]
		}
	}
	return -1, nil
}

func (f *Fallback) validTest() {
	wg := sync.WaitGroup{}
	wg.Add(len(f.proxies))

	for _, p := range f.proxies {
		go func(p *proxy) {
			_, err := DelayTest(p.RawProxy, f.rawURL)
			p.Valid = err == nil
			wg.Done()
		}(p)
	}

	wg.Wait()
}

func NewFallback(option FallbackOption, proxies []C.Proxy) (*Fallback, error) {
	_, err := urlToMetadata(option.URL)
	if err != nil {
		return nil, err
	}

	if len(proxies) < 1 {
		return nil, errors.New("The number of proxies cannot be 0")
	}

	interval := time.Duration(option.Interval) * time.Second
	warpperProxies := make([]*proxy, len(proxies))
	for idx := range proxies {
		warpperProxies[idx] = &proxy{
			RawProxy: proxies[idx],
			Valid:    true,
		}
	}

	Fallback := &Fallback{
		Base: &Base{
			name: option.Name,
			tp:   C.Fallback,
		},
		proxies:  warpperProxies,
		rawURL:   option.URL,
		interval: interval,
		done:     make(chan struct{}),
	}
	go Fallback.loop()
	return Fallback, nil
}
