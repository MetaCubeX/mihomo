package splithttp

import (
	"crypto/rand"
	"math/big"
	"net/http"
	"net/url"
	"strings"
)

type RangeConfig struct {
	From int32 `json:"from" proxy:"from"`
	To   int32 `json:"to" proxy:"to"`
}

func (c RangeConfig) rand() int32 {
	return int32(randBetween(int64(c.From), int64(c.To)))
}

type XmuxConfig struct {
	MaxConcurrency   *RangeConfig `json:"maxConcurrency" proxy:"max-concurrency"`
	MaxConnections   *RangeConfig `json:"maxConnections" proxy:"max-connections"`
	CMaxReuseTimes   *RangeConfig `json:"cMaxReuseTimes" proxy:"c-max-reuse-times"`
	HMaxRequestTimes *RangeConfig `json:"hMaxRequestTimes" proxy:"h-max-request-times"`
	HMaxReusableSecs *RangeConfig `json:"hMaxReusableSecs" proxy:"h-max-reusable-secs"`
	HKeepAlivePeriod int64        `json:"hKeepAlivePeriod" proxy:"h-keep-alive-period"`
}

type Config struct {
	Host                 string            `json:"host"`
	Path                 string            `json:"path"`
	Mode                 string            `json:"mode"`
	Headers              map[string]string `json:"headers"`
	XPaddingBytes        *RangeConfig      `json:"xPaddingBytes"`
	NoGRPCHeader         bool              `json:"noGRPCHeader"`
	ScMaxEachPostBytes   *RangeConfig      `json:"scMaxEachPostBytes"`
	ScMinPostsIntervalMs *RangeConfig      `json:"scMinPostsIntervalMs"`
	ScMaxBufferedPosts   int32             `json:"scMaxBufferedPosts"`
	ScStreamUpServerSecs *RangeConfig      `json:"scStreamUpServerSecs"`
	Xmux                 *XmuxConfig       `json:"xmux"`
	DownloadSettings     *Config           `json:"downloadSettings"` // Simplified for now, assume same protocol
}

func (c *Config) GetNormalizedPath() string {
	pathAndQuery := strings.SplitN(c.Path, "?", 2)
	path := pathAndQuery[0]

	if path == "" || path[0] != '/' {
		path = "/" + path
	}

	if path[len(path)-1] != '/' {
		path = path + "/"
	}

	return path
}

func (c *Config) GetNormalizedQuery() string {
	pathAndQuery := strings.SplitN(c.Path, "?", 2)
	query := ""

	if len(pathAndQuery) > 1 {
		query = pathAndQuery[1]
	}

	return query
}

func (c *Config) GetRequestHeader(rawURL string) http.Header {
	header := http.Header{}
	for k, v := range c.Headers {
		header.Add(k, v)
	}

	u, _ := url.Parse(rawURL)
	u.RawQuery = "x_padding=" + strings.Repeat("X", int(c.GetNormalizedXPaddingBytes().rand()))
	header.Set("Referer", u.String())

	return header
}

func (c *Config) WriteResponseHeader(writer http.ResponseWriter) {
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.Header().Set("Access-Control-Allow-Methods", "GET, POST")
	writer.Header().Set("X-Padding", strings.Repeat("X", int(c.GetNormalizedXPaddingBytes().rand())))
}

func (c *Config) GetNormalizedXPaddingBytes() RangeConfig {
	if c.XPaddingBytes == nil || c.XPaddingBytes.To == 0 {
		return RangeConfig{
			From: 100,
			To:   1000,
		}
	}

	return *c.XPaddingBytes
}

func (c *Config) GetNormalizedScMaxEachPostBytes() RangeConfig {
	if c.ScMaxEachPostBytes == nil || c.ScMaxEachPostBytes.To == 0 {
		return RangeConfig{
			From: 1000000,
			To:   1000000,
		}
	}

	return *c.ScMaxEachPostBytes
}

func (c *Config) GetNormalizedScMinPostsIntervalMs() RangeConfig {
	if c.ScMinPostsIntervalMs == nil || c.ScMinPostsIntervalMs.To == 0 {
		return RangeConfig{
			From: 30,
			To:   30,
		}
	}

	return *c.ScMinPostsIntervalMs
}

func (c *Config) GetNormalizedScMaxBufferedPosts() int {
	if c.ScMaxBufferedPosts == 0 {
		return 30
	}

	return int(c.ScMaxBufferedPosts)
}

func (c *Config) GetNormalizedScStreamUpServerSecs() RangeConfig {
	if c.ScStreamUpServerSecs == nil || c.ScStreamUpServerSecs.To == 0 {
		return RangeConfig{
			From: 20,
			To:   80,
		}
	}

	return *c.ScMinPostsIntervalMs
}

func (m *XmuxConfig) GetNormalizedMaxConcurrency() RangeConfig {
	if m.MaxConcurrency == nil {
		return RangeConfig{
			From: 0,
			To:   0,
		}
	}

	return *m.MaxConcurrency
}

func (m *XmuxConfig) GetNormalizedMaxConnections() RangeConfig {
	if m.MaxConnections == nil {
		return RangeConfig{
			From: 0,
			To:   0,
		}
	}

	return *m.MaxConnections
}

func (m *XmuxConfig) GetNormalizedCMaxReuseTimes() RangeConfig {
	if m.CMaxReuseTimes == nil {
		return RangeConfig{
			From: 0,
			To:   0,
		}
	}

	return *m.CMaxReuseTimes
}

func (m *XmuxConfig) GetNormalizedHMaxRequestTimes() RangeConfig {
	if m.HMaxRequestTimes == nil {
		return RangeConfig{
			From: 0,
			To:   0,
		}
	}

	return *m.HMaxRequestTimes
}

func (m *XmuxConfig) GetNormalizedHMaxReusableSecs() RangeConfig {
	if m.HMaxReusableSecs == nil {
		return RangeConfig{
			From: 0,
			To:   0,
		}
	}

	return *m.HMaxReusableSecs
}

func randBetween(min, max int64) int64 {
	if min == max {
		return min
	}
	if min > max {
		min, max = max, min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(max-min+1))
	return min + n.Int64()
}
