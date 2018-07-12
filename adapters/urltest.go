package adapters

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	C "github.com/Dreamacro/clash/constant"
)

type URLTest struct {
	name   string
	proxys []C.Proxy
	url    *url.URL
	rawURL string
	addr   *C.Addr
	fast   C.Proxy
	delay  time.Duration
	done   chan struct{}
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

func (u *URLTest) Generator(addr *C.Addr) (adapter C.ProxyAdapter, err error) {
	return u.fast.Generator(addr)
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
	wg.Add(len(u.proxys))
	c := make(chan interface{})
	fast := selectFast(c)
	timer := time.NewTimer(u.delay)

	for _, p := range u.proxys {
		go func(p C.Proxy) {
			err := getUrl(p, u.addr, u.rawURL)
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

func getUrl(proxy C.Proxy, addr *C.Addr, rawURL string) (err error) {
	instance, err := proxy.Generator(addr)
	if err != nil {
		return
	}
	defer instance.Close()
	transport := &http.Transport{
		Dial: func(string, string) (net.Conn, error) {
			return instance.Conn(), nil
		},
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := http.Client{Transport: transport}
	req, err := client.Get(rawURL)
	if err != nil {
		return
	}
	req.Body.Close()
	return nil
}

func selectFast(in chan interface{}) chan interface{} {
	out := make(chan interface{})
	go func() {
		p, open := <-in
		if open {
			out <- p
		}
		close(out)
		for range in {
		}
	}()

	return out
}

func NewURLTest(name string, proxys []C.Proxy, rawURL string, delay time.Duration) (*URLTest, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else if u.Scheme == "http" {
			port = "80"
		} else {
			return nil, fmt.Errorf("%s scheme not Support", rawURL)
		}
	}

	addr := &C.Addr{
		AddrType: C.AtypDomainName,
		Host:     u.Hostname(),
		IP:       nil,
		Port:     port,
	}

	urlTest := &URLTest{
		name:   name,
		proxys: proxys[:],
		rawURL: rawURL,
		url:    u,
		addr:   addr,
		fast:   proxys[0],
		delay:  delay,
		done:   make(chan struct{}),
	}
	go urlTest.loop()
	return urlTest, nil
}
