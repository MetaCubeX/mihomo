package adapters

import (
	"encoding/json"
	"errors"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/Dreamacro/clash/constant"
)

type URLTest struct {
	*Base
	proxies  []C.Proxy
	rawURL   string
	fast     C.Proxy
	interval time.Duration
	done     chan struct{}
	once     int32
}

type URLTestOption struct {
	Name     string   `proxy:"name"`
	Proxies  []string `proxy:"proxies"`
	URL      string   `proxy:"url"`
	Interval int      `proxy:"interval"`
}

func (u *URLTest) Now() string {
	return u.fast.Name()
}

func (u *URLTest) Generator(metadata *C.Metadata) (net.Conn, error) {
	a, err := u.fast.Generator(metadata)
	if err != nil {
		go u.speedTest()
	}
	return a, err
}

func (u *URLTest) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range u.proxies {
		all = append(all, proxy.Name())
	}
	sort.Strings(all)
	return json.Marshal(map[string]interface{}{
		"type": u.Type().String(),
		"now":  u.Now(),
		"all":  all,
	})
}

func (u *URLTest) Close() {
	u.done <- struct{}{}
}

func (u *URLTest) loop() {
	tick := time.NewTicker(u.interval)
	go u.speedTest()
Loop:
	for {
		select {
		case <-tick.C:
			go u.speedTest()
		case <-u.done:
			break Loop
		}
	}
}

func (u *URLTest) speedTest() {
	if atomic.AddInt32(&u.once, 1) != 1 {
		return
	}
	defer atomic.StoreInt32(&u.once, 0)

	wg := sync.WaitGroup{}
	wg.Add(len(u.proxies))
	c := make(chan interface{})
	fast := selectFast(c)
	timer := time.NewTimer(u.interval)

	for _, p := range u.proxies {
		go func(p C.Proxy) {
			_, err := DelayTest(p, u.rawURL)
			if err == nil {
				c <- p
			}
			wg.Done()
		}(p)
	}

	go func() {
		wg.Wait()
		close(c)
	}()

	select {
	case <-timer.C:
		// Wait for fast to return or close.
		<-fast
	case p, open := <-fast:
		if open {
			u.fast = p.(C.Proxy)
		}
	}
}

func NewURLTest(option URLTestOption, proxies []C.Proxy) (*URLTest, error) {
	_, err := urlToMetadata(option.URL)
	if err != nil {
		return nil, err
	}
	if len(proxies) < 1 {
		return nil, errors.New("The number of proxies cannot be 0")
	}

	interval := time.Duration(option.Interval) * time.Second
	urlTest := &URLTest{
		Base: &Base{
			name: option.Name,
			tp:   C.URLTest,
		},
		proxies:  proxies[:],
		rawURL:   option.URL,
		fast:     proxies[0],
		interval: interval,
		done:     make(chan struct{}),
		once:     0,
	}
	go urlTest.loop()
	return urlTest, nil
}
