package xhttp

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"strconv"
	"strings"

	"github.com/metacubex/http"
)

type Config struct {
	Host                 string
	Path                 string
	Mode                 string
	Headers              map[string]string
	NoGRPCHeader         bool
	XPaddingBytes        string
	NoSSEHeader          bool   // server only
	ScStreamUpServerSecs string // server only
	ScMaxEachPostBytes   string
	ReuseConfig          *ReuseConfig
	DownloadConfig       *Config
}

type ReuseConfig struct {
	MaxConnections   string
	MaxConcurrency   string
	CMaxReuseTimes   string
	HMaxRequestTimes string
	HMaxReusableSecs string
}

func (c *Config) NormalizedMode() string {
	if c.Mode == "" {
		return "auto"
	}
	return c.Mode
}

func (c *Config) EffectiveMode(hasReality bool) string {
	mode := c.NormalizedMode()
	if mode != "auto" {
		return mode
	}
	if hasReality {
		if c.DownloadConfig != nil {
			return "stream-up"
		}
		return "stream-one"
	}
	return "packet-up"
}

func (c *Config) NormalizedPath() string {
	path := c.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	return path
}

func (c *Config) RequestHeader() http.Header {
	h := http.Header{}
	for k, v := range c.Headers {
		h.Set(k, v)
	}

	if h.Get("User-Agent") == "" {
		h.Set("User-Agent", "Mozilla/5.0")
	}
	if h.Get("Accept") == "" {
		h.Set("Accept", "*/*")
	}
	if h.Get("Accept-Language") == "" {
		h.Set("Accept-Language", "en-US,en;q=0.9")
	}
	if h.Get("Cache-Control") == "" {
		h.Set("Cache-Control", "no-cache")
	}
	if h.Get("Pragma") == "" {
		h.Set("Pragma", "no-cache")
	}

	return h
}

func (c *Config) RandomPadding() (string, error) {
	r, err := ParseRange(c.XPaddingBytes, "100-1000")
	if err != nil {
		return "", fmt.Errorf("invalid x-padding-bytes: %w", err)
	}
	return strings.Repeat("X", r.Rand()), nil
}

func (c *Config) GetNormalizedScStreamUpServerSecs() (Range, error) {
	r, err := ParseRange(c.ScStreamUpServerSecs, "20-80")
	if err != nil {
		return Range{}, fmt.Errorf("invalid sc-stream-up-server-secs: %w", err)
	}
	return r, nil
}

func (c *Config) GetNormalizedScMaxEachPostBytes() (Range, error) {
	r, err := ParseRange(c.ScStreamUpServerSecs, "1000000")
	if err != nil {
		return Range{}, fmt.Errorf("invalid sc-max-each-post-bytes: %w", err)
	}
	if r.Max == 0 {
		return Range{}, fmt.Errorf("invalid sc-max-each-post-bytes: must be greater than zero")
	}
	return r, nil
}

type Range struct {
	Min int
	Max int
}

func (r Range) Rand() int {
	if r.Min == r.Max {
		return r.Min
	}
	return r.Min + rand.Intn(r.Max-r.Min+1)
}

func ParseRange(s string, fallback string) (Range, error) {
	if strings.TrimSpace(s) == "" {
		return parseRange(fallback)
	}
	return parseRange(s)
}

func parseRange(s string) (Range, error) {
	parts := strings.Split(strings.TrimSpace(s), "-")
	if len(parts) == 1 {
		v, err := strconv.Atoi(parts[0])
		if err != nil {
			return Range{}, err
		}
		return Range{v, v}, nil
	}
	if len(parts) != 2 {
		return Range{}, fmt.Errorf("invalid range: %s", s)
	}

	minVal, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return Range{}, err
	}
	maxVal, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return Range{}, err
	}
	if minVal < 0 || maxVal < minVal {
		return Range{}, fmt.Errorf("invalid range: %s", s)
	}
	return Range{minVal, maxVal}, nil
}

func (c *ReuseConfig) ResolveManagerConfig() (Range, Range, error) {
	if c == nil {
		return Range{}, Range{}, nil
	}

	maxConnections, err := ParseRange(c.MaxConnections, "0")
	if err != nil {
		return Range{}, Range{}, fmt.Errorf("invalid max-connections: %w", err)
	}

	maxConcurrency, err := ParseRange(c.MaxConcurrency, "0")
	if err != nil {
		return Range{}, Range{}, fmt.Errorf("invalid max-concurrency: %w", err)
	}

	return maxConnections, maxConcurrency, nil
}

func (c *ReuseConfig) ResolveEntryConfig() (Range, Range, Range, error) {
	if c == nil {
		return Range{}, Range{}, Range{}, nil
	}

	hMaxRequestTimes, err := ParseRange(c.HMaxRequestTimes, "0")
	if err != nil {
		return Range{}, Range{}, Range{}, fmt.Errorf("invalid h-max-request-times: %w", err)
	}

	hMaxReusableSecs, err := ParseRange(c.HMaxReusableSecs, "0")
	if err != nil {
		return Range{}, Range{}, Range{}, fmt.Errorf("invalid h-max-reusable-secs: %w", err)
	}

	cMaxReuseTimes, err := ParseRange(c.CMaxReuseTimes, "0")
	if err != nil {
		return Range{}, Range{}, Range{}, fmt.Errorf("invalid c-max-reuse-times: %w", err)
	}

	return hMaxRequestTimes, hMaxReusableSecs, cMaxReuseTimes, nil
}

func (c *Config) FillStreamRequest(req *http.Request, sessionID string) error {
	req.Header = c.RequestHeader()

	paddingValue, err := c.RandomPadding()
	if err != nil {
		return err
	}

	if paddingValue != "" {
		rawURL := req.URL.String()
		sep := "?"
		if strings.Contains(rawURL, "?") {
			sep = "&"
		}
		req.Header.Set("Referer", rawURL+sep+"x_padding="+paddingValue)
	}

	c.ApplyMetaToRequest(req, sessionID, "")

	if req.Body != nil && !c.NoGRPCHeader {
		req.Header.Set("Content-Type", "application/grpc")
	}

	return nil
}

func appendToPath(path, value string) string {
	if strings.HasSuffix(path, "/") {
		return path + value
	}
	return path + "/" + value
}

func (c *Config) ApplyMetaToRequest(req *http.Request, sessionID string, seqStr string) {
	if sessionID != "" {
		req.URL.Path = appendToPath(req.URL.Path, sessionID)
	}
	if seqStr != "" {
		req.URL.Path = appendToPath(req.URL.Path, seqStr)
	}
}

func (c *Config) FillPacketRequest(req *http.Request, sessionID string, seqStr string, payload []byte) error {
	req.Header = c.RequestHeader()
	req.Body = io.NopCloser(bytes.NewReader(payload))
	req.ContentLength = int64(len(payload))

	paddingValue, err := c.RandomPadding()
	if err != nil {
		return err
	}
	if paddingValue != "" {
		rawURL := req.URL.String()
		sep := "?"
		if strings.Contains(rawURL, "?") {
			sep = "&"
		}
		req.Header.Set("Referer", rawURL+sep+"x_padding="+paddingValue)
	}

	c.ApplyMetaToRequest(req, sessionID, seqStr)
	return nil
}

func (c *Config) FillDownloadRequest(req *http.Request, sessionID string) error {
	req.Header = c.RequestHeader()

	paddingValue, err := c.RandomPadding()
	if err != nil {
		return err
	}
	if paddingValue != "" {
		rawURL := req.URL.String()
		sep := "?"
		if strings.Contains(rawURL, "?") {
			sep = "&"
		}
		req.Header.Set("Referer", rawURL+sep+"x_padding="+paddingValue)
	}

	c.ApplyMetaToRequest(req, sessionID, "")
	return nil
}
