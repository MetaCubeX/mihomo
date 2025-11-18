package xhttp

import (
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	tls "github.com/metacubex/utls"
)

// Config holds SplitHTTP client settings.
type Config struct {
	Host                 string            `proxy:"host" json:"host"`
	Path                 string            `proxy:"path" json:"path"`
	Mode                 string            `proxy:"mode" json:"mode"`
	Headers              map[string]string `proxy:"headers" json:"headers"`
	NoGRPCHeader         bool              `proxy:"no-grpc-header" json:"no-grpc-header"`
	NoSSEHeader          bool              `proxy:"no-sse-header" json:"no-sse-header"`
	HTTPVersion          string            `proxy:"http-version" json:"http-version"`
	XPaddingBytes        Range             `proxy:"x-padding-bytes" json:"x-padding-bytes"`
	ScMaxEachPostBytes   Range             `proxy:"sc-max-each-post-bytes" json:"sc-max-each-post-bytes"`
	ScMinPostsIntervalMs Range             `proxy:"sc-min-posts-interval-ms" json:"sc-min-posts-interval-ms"`
	ScStreamUpServerSecs Range             `proxy:"sc-stream-up-server-secs" json:"sc-stream-up-server-secs"`
	Xmux                 *XmuxConfig       `proxy:"xmux" json:"xmux"`
	Download             *Config           `proxy:"download-settings" json:"download-settings"`

	internalTLS *tls.Config `json:"-"`
}

func (c *Config) clone() *Config {
	if c == nil {
		return defaultConfig()
	}
	cp := *c
	if len(c.Headers) != 0 {
		cp.Headers = make(map[string]string, len(c.Headers))
		for k, v := range c.Headers {
			cp.Headers[k] = v
		}
	}
	if c.Download != nil {
		cp.Download = c.Download.clone()
	}
	if c.Xmux != nil {
		cp.Xmux = c.Xmux.clone()
	}
	return &cp
}

func defaultConfig() *Config {
	return &Config{
		Path:                 "/",
		XPaddingBytes:        Range{From: 100, To: 1000},
		ScMaxEachPostBytes:   Range{From: 1_000_000, To: 1_000_000},
		ScMinPostsIntervalMs: Range{From: 30, To: 30},
	}
}

func (c *Config) normalize() {
	if c == nil {
		return
	}
	c.Path = normalizePath(c.Path)
	c.XPaddingBytes = c.XPaddingBytes.WithDefault(100, 1000)
	c.ScMaxEachPostBytes = c.ScMaxEachPostBytes.WithDefault(1_000_000, 1_000_000)
	c.ScMinPostsIntervalMs = c.ScMinPostsIntervalMs.WithDefault(30, 30)
	c.Mode = strings.ToLower(c.Mode)
	switch c.Mode {
	case "", "auto", "packet-up", "stream-up", "stream-one":
	default:
		c.Mode = "packet-up"
	}
	if c.Xmux == nil {
		c.Xmux = &XmuxConfig{}
	}
	c.Xmux.normalize()
}

func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return path.Clean(p) + "/"
}

func withPadding(rawURL string, padding int) string {
	if padding <= 0 {
		padding = 1
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	query := u.Query()
	query.Set("x_padding", strings.Repeat("X", padding))
	u.RawQuery = query.Encode()
	return u.String()
}

func (c *Config) validate() error {
	if c == nil {
		return fmt.Errorf("xhttp config is nil")
	}
	if c.Host != "" && strings.Contains(c.Host, "://") {
		return fmt.Errorf("xhttp host should not include scheme")
	}
	return nil
}

func (c *Config) httpVersion(defaultSecure bool) string {
	version := strings.TrimSpace(strings.ToLower(c.HTTPVersion))
	switch version {
	case "", "auto":
		if defaultSecure {
			return "2"
		}
		return "1.1"
	case "1", "1.1", "h1":
		return "1.1"
	case "2", "h2":
		return "2"
	case "3", "h3":
		return "3"
	default:
		return "1.1"
	}
}

func (c *Config) WithInternalTLS(tlsCfg *tls.Config) {
	c.internalTLS = tlsCfg
}

func (c *Config) internalTLSConfig() *tls.Config {
	return c.internalTLS
}

func (c *Config) Clone() *Config {
	return c.clone()
}

func (c *Config) normalizedXmux() normalizedXmux {
	if c == nil || c.Xmux == nil {
		return defaultXmux()
	}
	return c.Xmux.normalized()
}

type XmuxConfig struct {
	MaxConcurrency   Range `proxy:"max-concurrency" json:"max-concurrency"`
	MaxConnections   Range `proxy:"max-connections" json:"max-connections"`
	CMaxReuseTimes   Range `proxy:"c-max-reuse-times" json:"c-max-reuse-times"`
	HMaxRequestTimes Range `proxy:"h-max-request-times" json:"h-max-request-times"`
	HMaxReusableSecs Range `proxy:"h-max-reusable-secs" json:"h-max-reusable-secs"`
	HKeepAlivePeriod int   `proxy:"h-keep-alive-period" json:"h-keep-alive-period"`
}

func (x *XmuxConfig) clone() *XmuxConfig {
	if x == nil {
		return nil
	}
	cp := *x
	return &cp
}

func (x *XmuxConfig) normalize() {
	if x == nil {
		return
	}
}

type normalizedXmux struct {
	maxConcurrency int32
	maxConnections int
	reuseRange     Range
	requestRange   Range
	reusableRange  Range
	keepAlive      time.Duration
}

func defaultXmux() normalizedXmux {
	return normalizedXmux{
		maxConcurrency: 1,
		maxConnections: 0,
		reuseRange:     Range{},
		requestRange:   Range{From: 600, To: 900},
		reusableRange:  Range{From: 1800, To: 3000},
		keepAlive:      30 * time.Second,
	}
}

func (x *XmuxConfig) normalized() normalizedXmux {
	if x == nil {
		return defaultXmux()
	}
	n := defaultXmux()
	if v := x.MaxConcurrency.WithDefault(n.maxConcurrency, n.maxConcurrency); v.To >= v.From {
		n.maxConcurrency = v.Random()
	}
	if v := x.MaxConnections.WithDefault(0, 0); v.To >= v.From {
		n.maxConnections = int(v.Random())
	}
	if !x.CMaxReuseTimes.IsZero() {
		n.reuseRange = x.CMaxReuseTimes
	}
	if !x.HMaxRequestTimes.IsZero() {
		n.requestRange = x.HMaxRequestTimes
	}
	if !x.HMaxReusableSecs.IsZero() {
		n.reusableRange = x.HMaxReusableSecs
	}
	if x.HKeepAlivePeriod > 0 {
		n.keepAlive = time.Duration(x.HKeepAlivePeriod) * time.Second
	}
	return n
}

func (n normalizedXmux) newSlotLimits() (int32, int32, time.Time) {
	var uses int32
	if !n.reuseRange.IsZero() {
		uses = n.reuseRange.Random()
	}
	var requests int32
	if !n.requestRange.IsZero() {
		requests = n.requestRange.Random()
		if requests <= 0 {
			requests = 1
		}
	}
	expiry := time.Time{}
	if !n.reusableRange.IsZero() {
		secs := n.reusableRange.Random()
		if secs > 0 {
			expiry = time.Now().Add(time.Duration(secs) * time.Second)
		}
	}
	return uses, requests, expiry
}
