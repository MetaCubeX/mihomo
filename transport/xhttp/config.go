package xhttp

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"strconv"
	"strings"

	tlsC "github.com/metacubex/mihomo/component/tls"

	"github.com/metacubex/http"
)

type Config struct {
	Host             string
	Path             string
	Mode             string
	Headers          map[string]string
	NoGRPCHeader     bool
	XPaddingBytes    string
	ALPN             []string
	TryQUIC          bool
	HasReality       bool
	DownloadSettings *DownloadConfig
}

type DownloadConfig struct {
	Server            string
	Port              int
	TLS               *bool
	Headers           map[string]string
	Host              string
	Path              string
	Mode              string
	ServerName        string
	ClientFingerprint string
	SkipCertVerify    bool
	Reality           *tlsC.RealityConfig
}

func (c *Config) NormalizedMode() string {
	if c.Mode == "" {
		return "auto"
	}
	return c.Mode
}

func (c *Config) EffectiveModeWithReality(hasReality bool) string {
	return c.effectiveMode(hasReality)
}

func (c *Config) effectiveMode(hasReality bool) string {
	mode := c.NormalizedMode()
	if mode != "auto" {
		return mode
	}
	if c.DownloadSettings != nil {
		return "stream-up"
	}
	if hasReality {
		return "stream-one"
	}
	if c.SupportsHTTP2() {
		return "stream-up"
	}
	return "packet-up"
}

func (c *Config) EffectiveMode() string {
	return c.effectiveMode(c.HasReality)
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

func (c *Config) HasALPN(token string) bool {
	token = strings.ToLower(strings.TrimSpace(token))
	if token == "" {
		return false
	}
	for _, item := range c.ALPN {
		if strings.ToLower(strings.TrimSpace(item)) == token {
			return true
		}
	}
	return false
}

func (c *Config) SupportsHTTP2() bool {
	if len(c.ALPN) == 0 {
		return true
	}
	return c.HasALPN("h2")
}

func (c *Config) ShouldTryHTTP3() bool {
	return c.TryQUIC && c.HasALPN("h3")
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

func (c *Config) DownloadRequestConfig() *Config {
	if c.DownloadSettings == nil {
		return c
	}

	download := &Config{
		Host:          c.Host,
		Path:          c.Path,
		Mode:          c.Mode,
		Headers:       c.Headers,
		NoGRPCHeader:  c.NoGRPCHeader,
		XPaddingBytes: c.XPaddingBytes,
		ALPN:          c.ALPN,
		TryQUIC:       c.TryQUIC,
		HasReality:    c.HasReality,
	}

	if c.DownloadSettings.Host != "" {
		download.Host = c.DownloadSettings.Host
	}
	if c.DownloadSettings.Path != "" {
		download.Path = c.DownloadSettings.Path
	}
	if c.DownloadSettings.Mode != "" {
		download.Mode = c.DownloadSettings.Mode
	}
	if len(c.DownloadSettings.Headers) != 0 {
		download.Headers = c.DownloadSettings.Headers
	}

	return download
}
