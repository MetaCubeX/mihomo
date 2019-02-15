package adapters

import (
	"encoding/json"
	"errors"
	"net"

	"github.com/Dreamacro/clash/common/murmur3"
	C "github.com/Dreamacro/clash/constant"

	"golang.org/x/net/publicsuffix"
)

type LoadBalance struct {
	*Base
	proxies  []C.Proxy
	maxRetry int
}

func getKey(metadata *C.Metadata) string {
	if metadata.Host != "" {
		// ip host
		if ip := net.ParseIP(metadata.Host); ip != nil {
			return metadata.Host
		}

		if etld, err := publicsuffix.EffectiveTLDPlusOne(metadata.Host); err == nil {
			return etld
		}
	}

	if metadata.IP == nil {
		return ""
	}

	return metadata.IP.String()
}

func jumpHash(key uint64, buckets int32) int32 {
	var b, j int64

	for j < int64(buckets) {
		b = j
		key = key*2862933555777941757 + 1
		j = int64(float64(b+1) * (float64(int64(1)<<31) / float64((key>>33)+1)))
	}

	return int32(b)
}

func (lb *LoadBalance) Generator(metadata *C.Metadata) (net.Conn, error) {
	key := uint64(murmur3.Sum32([]byte(getKey(metadata))))
	buckets := int32(len(lb.proxies))
	for i := 0; i < lb.maxRetry; i++ {
		idx := jumpHash(key, buckets)
		if proxy, err := lb.proxies[idx].Generator(metadata); err == nil {
			return proxy, nil
		}
		key++
	}

	return lb.proxies[0].Generator(metadata)
}

func (lb *LoadBalance) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range lb.proxies {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]interface{}{
		"type": lb.Type().String(),
		"all":  all,
	})
}

type LoadBalanceOption struct {
	Name    string   `proxy:"name"`
	Proxies []string `proxy:"proxies"`
}

func NewLoadBalance(name string, proxies []C.Proxy) (*LoadBalance, error) {
	if len(proxies) == 0 {
		return nil, errors.New("Provide at least one proxy")
	}

	return &LoadBalance{
		Base: &Base{
			name: name,
			tp:   C.LoadBalance,
		},
		proxies:  proxies,
		maxRetry: 3,
	}, nil
}
