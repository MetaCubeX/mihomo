package adapters

import (
	"errors"
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

type URLTestOption struct {
	Name    string   `proxy:"name"`
	Proxies []string `proxy:"proxies"`
	URL     string   `proxy:"url"`
	Delay   int      `proxy:"delay"`
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

func NewURLTest(option URLTestOption, proxies []C.Proxy) (*URLTest, error) {
	_, err := urlToMetadata(option.URL)
	if err != nil {
		return nil, err
	}
	if len(proxies) < 1 {
		return nil, errors.New("The number of proxies cannot be 0")
	}

	delay := time.Duration(option.Delay) * time.Second
	urlTest := &URLTest{
		name:    option.Name,
		proxies: proxies[:],
		rawURL:  option.URL,
		fast:    proxies[0],
		delay:   delay,
		done:    make(chan struct{}),
	}
	go urlTest.loop()
	return urlTest, nil
}
