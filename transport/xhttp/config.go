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
	Host           string
	Path           string
	Mode           string
	Headers        map[string]string
	NoGRPCHeader   bool
	XPaddingBytes  string
	DownloadConfig *Config
	XMux           *XMuxConfig
}

type DownloadConfig struct {
	Host              string
	Path              string
	Mode              string
	ServerName        string
	ClientFingerprint string
	SkipCertVerify    bool
}

type XMuxConfig struct {
	MaxConnections   string      `proxy:"max-connections,omitempty"`
	MaxConcurrency   string      `proxy:"max-concurrency,omitempty"`
	CMaxReuseTimes   string      `proxy:"c-max-reuse-times,omitempty"`
	HMaxRequestTimes string      `proxy:"h-max-request-times,omitempty"`
	HMaxReusableSecs string      `proxy:"h-max-reusable-secs,omitempty"`
	Download         *XMuxConfig `proxy:"download,omitempty"`
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
	paddingRange := c.XPaddingBytes
	if paddingRange == "" {
		paddingRange = "100-1000"
	}

	minVal, maxVal, err := parseRange(paddingRange)
	if err != nil {
		return "", err
	}
	if minVal < 0 || maxVal < minVal {
		return "", fmt.Errorf("invalid x-padding-bytes range: %s", paddingRange)
	}
	if maxVal == 0 {
		return "", nil
	}

	n := minVal
	if maxVal > minVal {
		n = minVal + rand.Intn(maxVal-minVal+1)
	}

	return strings.Repeat("X", n), nil
}

func parseRange(s string) (int, int, error) {
	parts := strings.Split(strings.TrimSpace(s), "-")
	if len(parts) == 1 {
		v, err := strconv.Atoi(parts[0])
		if err != nil {
			return 0, 0, err
		}
		return v, v, nil
	}
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid range: %s", s)
	}

	minVal, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, err
	}
	maxVal, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, err
	}
	return minVal, maxVal, nil
}

func resolveRangeValue(s string, fallback int) (int, error) {
	if strings.TrimSpace(s) == "" {
		return fallback, nil
	}

	minVal, maxVal, err := parseRange(s)
	if err != nil {
		return 0, err
	}
	if minVal < 0 || maxVal < minVal {
		return 0, fmt.Errorf("invalid range: %s", s)
	}

	if minVal == maxVal {
		return minVal, nil
	}

	return minVal + rand.Intn(maxVal-minVal+1), nil
}

func (c *XMuxConfig) ResolveManagerConfig() (int, int, error) {
	if c == nil {
		return 0, 0, nil
	}

	maxConnections, err := resolveRangeValue(c.MaxConnections, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid xmux max-connections: %w", err)
	}

	maxConcurrency, err := resolveRangeValue(c.MaxConcurrency, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid xmux max-concurrency: %w", err)
	}

	return maxConnections, maxConcurrency, nil
}

func (c *XMuxConfig) ResolveConnReuseConfig() (int, error) {
	if c == nil {
		return 0, nil
	}

	cMaxReuseTimes, err := resolveRangeValue(c.CMaxReuseTimes, 0)
	if err != nil {
		return 0, fmt.Errorf("invalid xmux c-max-reuse-times: %w", err)
	}

	return cMaxReuseTimes, nil
}

func (c *XMuxConfig) ResolveEntryConfig() (int, int, error) {
	if c == nil {
		return 0, 0, nil
	}

	hMaxRequestTimes, err := resolveRangeValue(c.HMaxRequestTimes, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid xmux h-max-request-times: %w", err)
	}

	hMaxReusableSecs, err := resolveRangeValue(c.HMaxReusableSecs, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid xmux h-max-reusable-secs: %w", err)
	}

	return hMaxRequestTimes, hMaxReusableSecs, nil
}

func (c *XMuxConfig) ResolveDownloadConnReuseConfig() (int, error) {
	if c == nil {
		return 0, nil
	}
	if c.Download == nil {
		return c.ResolveConnReuseConfig()
	}

	cMaxReuseTimes := c.Download.CMaxReuseTimes
	if strings.TrimSpace(cMaxReuseTimes) == "" {
		cMaxReuseTimes = c.CMaxReuseTimes
	}

	resolvedCMaxReuseTimes, err := resolveRangeValue(cMaxReuseTimes, 0)
	if err != nil {
		return 0, fmt.Errorf("invalid xmux download c-max-reuse-times: %w", err)
	}

	return resolvedCMaxReuseTimes, nil
}

func (c *XMuxConfig) ResolveDownloadManagerConfig() (int, int, error) {
	if c == nil {
		return 0, 0, nil
	}
	if c.Download == nil {
		return c.ResolveManagerConfig()
	}

	maxConnections := c.Download.MaxConnections
	if strings.TrimSpace(maxConnections) == "" {
		maxConnections = c.MaxConnections
	}

	maxConcurrency := c.Download.MaxConcurrency
	if strings.TrimSpace(maxConcurrency) == "" {
		maxConcurrency = c.MaxConcurrency
	}

	resolvedMaxConnections, err := resolveRangeValue(maxConnections, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid xmux download max-connections: %w", err)
	}

	resolvedMaxConcurrency, err := resolveRangeValue(maxConcurrency, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid xmux download max-concurrency: %w", err)
	}

	return resolvedMaxConnections, resolvedMaxConcurrency, nil
}

func (c *XMuxConfig) ResolveDownloadEntryConfig() (int, int, error) {
	if c == nil {
		return 0, 0, nil
	}
	if c.Download == nil {
		return c.ResolveEntryConfig()
	}

	hMaxRequestTimes := c.Download.HMaxRequestTimes
	if strings.TrimSpace(hMaxRequestTimes) == "" {
		hMaxRequestTimes = c.HMaxRequestTimes
	}

	hMaxReusableSecs := c.Download.HMaxReusableSecs
	if strings.TrimSpace(hMaxReusableSecs) == "" {
		hMaxReusableSecs = c.HMaxReusableSecs
	}

	resolvedHMaxRequestTimes, err := resolveRangeValue(hMaxRequestTimes, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid xmux download h-max-request-times: %w", err)
	}

	resolvedHMaxReusableSecs, err := resolveRangeValue(hMaxReusableSecs, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid xmux download h-max-reusable-secs: %w", err)
	}

	return resolvedHMaxRequestTimes, resolvedHMaxReusableSecs, nil
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
