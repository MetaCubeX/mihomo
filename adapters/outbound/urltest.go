package adapters

import (
	"sync"
	"time"

	C "github.com/Dreamacro/clash/constant"
)

type URLTest struct {
	name    string
	proxies []C.Proxy
	rawURL  string
	fast    C.Proxy
	delay   time.Duration
	done    chan struct{}
}

func (u *URLTest) Name() string {
	return u.name
}

func (u *URLTest) Type() C.AdapterType {
	return C.URLTest
}

func (u *URLTest) Now() string {
	return u.fast.Name()
}

func (u *URLTest) Generator(metadata *C.Metadata) (adapter C.ProxyAdapter, err error) {
	return u.fast.Generator(metadata)
}

func (u *URLTest) Close() {
	u.done <- struct{}{}
}

func (u *URLTest) loop() {
	tick := time.NewTicker(u.delay)
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
	wg := sync.WaitGroup{}
	wg.Add(len(u.proxies))
	c := make(chan interface{})
	fast := selectFast(c)
	timer := time.NewTimer(u.delay)

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

func NewURLTest(name string, proxies []C.Proxy, rawURL string, delay time.Duration) (*URLTest, error) {
	_, err := urlToMetadata(rawURL)
	if err != nil {
		return nil, err
	}

	urlTest := &URLTest{
		name:    name,
		proxies: proxies[:],
		rawURL:  rawURL,
		fast:    proxies[0],
		delay:   delay,
		done:    make(chan struct{}),
	}
	go urlTest.loop()
	return urlTest, nil
}
