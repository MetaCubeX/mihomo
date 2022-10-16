package acl

import (
	"bufio"
	"net"
	"os"
	"strings"

	"github.com/Dreamacro/clash/transport/hysteria/utils"
	lru "github.com/hashicorp/golang-lru"
	"github.com/oschwald/geoip2-golang"
)

const entryCacheSize = 1024

type Engine struct {
	DefaultAction Action
	Entries       []Entry
	Cache         *lru.ARCCache
	ResolveIPAddr func(string) (*net.IPAddr, error)
	GeoIPReader   *geoip2.Reader
}

type cacheKey struct {
	Host  string
	Port  uint16
	IsUDP bool
}

type cacheValue struct {
	Action Action
	Arg    string
}

func LoadFromFile(filename string, resolveIPAddr func(string) (*net.IPAddr, error), geoIPLoadFunc func() (*geoip2.Reader, error)) (*Engine, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	entries := make([]Entry, 0, 1024)
	var geoIPReader *geoip2.Reader
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			// Ignore empty lines & comments
			continue
		}
		entry, err := ParseEntry(line)
		if err != nil {
			return nil, err
		}
		if _, ok := entry.Matcher.(*countryMatcher); ok && geoIPReader == nil {
			geoIPReader, err = geoIPLoadFunc() // lazy load GeoIP reader only when needed
			if err != nil {
				return nil, err
			}
		}
		entries = append(entries, entry)
	}
	cache, err := lru.NewARC(entryCacheSize)
	if err != nil {
		return nil, err
	}
	return &Engine{
		DefaultAction: ActionProxy,
		Entries:       entries,
		Cache:         cache,
		ResolveIPAddr: resolveIPAddr,
		GeoIPReader:   geoIPReader,
	}, nil
}

// action, arg, isDomain, resolvedIP, error
func (e *Engine) ResolveAndMatch(host string, port uint16, isUDP bool) (Action, string, bool, *net.IPAddr, error) {
	ip, zone := utils.ParseIPZone(host)
	if ip == nil {
		// Domain
		ipAddr, err := e.ResolveIPAddr(host)
		if v, ok := e.Cache.Get(cacheKey{host, port, isUDP}); ok {
			// Cache hit
			ce := v.(cacheValue)
			return ce.Action, ce.Arg, true, ipAddr, err
		}
		for _, entry := range e.Entries {
			mReq := MatchRequest{
				Domain: host,
				Port:   port,
				DB:     e.GeoIPReader,
			}
			if ipAddr != nil {
				mReq.IP = ipAddr.IP
			}
			if isUDP {
				mReq.Protocol = ProtocolUDP
			} else {
				mReq.Protocol = ProtocolTCP
			}
			if entry.Match(mReq) {
				e.Cache.Add(cacheKey{host, port, isUDP},
					cacheValue{entry.Action, entry.ActionArg})
				return entry.Action, entry.ActionArg, true, ipAddr, err
			}
		}
		e.Cache.Add(cacheKey{host, port, isUDP}, cacheValue{e.DefaultAction, ""})
		return e.DefaultAction, "", true, ipAddr, err
	} else {
		// IP
		if v, ok := e.Cache.Get(cacheKey{ip.String(), port, isUDP}); ok {
			// Cache hit
			ce := v.(cacheValue)
			return ce.Action, ce.Arg, false, &net.IPAddr{
				IP:   ip,
				Zone: zone,
			}, nil
		}
		for _, entry := range e.Entries {
			mReq := MatchRequest{
				IP:   ip,
				Port: port,
				DB:   e.GeoIPReader,
			}
			if isUDP {
				mReq.Protocol = ProtocolUDP
			} else {
				mReq.Protocol = ProtocolTCP
			}
			if entry.Match(mReq) {
				e.Cache.Add(cacheKey{ip.String(), port, isUDP},
					cacheValue{entry.Action, entry.ActionArg})
				return entry.Action, entry.ActionArg, false, &net.IPAddr{
					IP:   ip,
					Zone: zone,
				}, nil
			}
		}
		e.Cache.Add(cacheKey{ip.String(), port, isUDP}, cacheValue{e.DefaultAction, ""})
		return e.DefaultAction, "", false, &net.IPAddr{
			IP:   ip,
			Zone: zone,
		}, nil
	}
}
