package adapters

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	C "github.com/Dreamacro/clash/constant"
)

type Base struct {
	name string
	tp   C.AdapterType
}

func (b *Base) Name() string {
	return b.name
}

func (b *Base) Type() C.AdapterType {
	return b.tp
}

func (b *Base) Destroy() {}

func (b *Base) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"type": b.Type().String(),
	})
}

type Proxy struct {
	C.ProxyAdapter
	alive bool
}

func (p *Proxy) Alive() bool {
	return p.alive
}

func (p *Proxy) Dial(metadata *C.Metadata) (net.Conn, error) {
	conn, err := p.ProxyAdapter.Dial(metadata)
	p.alive = err == nil
	return conn, err
}

// URLTest get the delay for the specified URL
func (p *Proxy) URLTest(url string) (t int16, err error) {
	addr, err := urlToMetadata(url)
	if err != nil {
		return
	}

	start := time.Now()
	instance, err := p.ProxyAdapter.Dial(&addr)
	if err != nil {
		return
	}
	defer instance.Close()
	transport := &http.Transport{
		Dial: func(string, string) (net.Conn, error) {
			return instance, nil
		},
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := http.Client{Transport: transport}
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	resp.Body.Close()
	t = int16(time.Since(start) / time.Millisecond)
	return
}

func NewProxy(adapter C.ProxyAdapter) *Proxy {
	return &Proxy{adapter, true}
}
