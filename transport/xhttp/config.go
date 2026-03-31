package xhttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/metacubex/http"
)

const (
	PlacementQueryInHeader = "queryInHeader"
	PlacementCookie        = "cookie"
	PlacementHeader        = "header"
	PlacementQuery         = "query"
	PlacementPath          = "path"
	PlacementBody          = "body"
	PlacementAuto          = "auto"
)

type PaddingMethod string

const (
	PaddingMethodRepeatX  PaddingMethod = "repeat-x"
	PaddingMethodTokenish PaddingMethod = "tokenish"
)

type RangeConfig struct {
	From int
	To   int
}

type SplitHTTPConfig struct {
	Host               string
	Path               string
	ALPN               []string
	DialAddr           string
	H3PacketDial       func(ctx context.Context, rAddr *net.UDPAddr) (net.PacketConn, error)
	H1UploadDial       func(ctx context.Context) (net.Conn, error)
	TLSServerName      string
	Headers            http.Header
	MaxUploadSize      int
	MaxConcurrentPosts int
	Mode               string
	TLS                bool

	XPaddingBytes       *RangeConfig
	XPaddingObfsMode    bool
	XPaddingKey         string
	XPaddingHeader      string
	XPaddingPlacement   string
	XPaddingMethod      string
	UplinkHTTPMethod    string
	SessionPlacement    string
	SessionKey          string
	SeqPlacement        string
	SeqKey              string
	UplinkDataPlacement string
	UplinkDataKey       string
	RequestLog          bool
	TryQUIC             bool
}

func (c *SplitHTTPConfig) HasALPN(token string) bool {
	if token == "" {
		return false
	}
	token = strings.ToLower(token)
	for _, p := range c.ALPN {
		if strings.ToLower(strings.TrimSpace(p)) == token {
			return true
		}
	}
	return false
}

func (c *SplitHTTPConfig) HasTCPFallback() bool {
	if len(c.ALPN) == 0 {
		return true
	}
	return c.HasALPN("h2") || c.HasALPN("http/1.1") || c.HasALPN("http/1.0")
}

func (c *SplitHTTPConfig) IsHTTPProtoAllowed(proto string) bool {
	if len(c.ALPN) == 0 {
		return true
	}
	allowed := map[string]bool{}
	for _, p := range c.ALPN {
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "h3":
			allowed["HTTP/3"] = true
		case "h2":
			allowed["HTTP/2"] = true
			allowed["HTTP/1.1"] = true
		case "http/1.1":
			allowed["HTTP/1.1"] = true
			// User-required behavior: when declared as HTTP/1.1, still allow/try h2 upgrade.
			allowed["HTTP/2"] = true
		case "http/1.0":
			allowed["HTTP/1.0"] = true
		}
	}
	if len(allowed) == 0 {
		return true
	}
	for ap := range allowed {
		if strings.HasPrefix(proto, ap) {
			return true
		}
	}
	return false
}

func (c *SplitHTTPConfig) GetNormalizedPath() string {
	pathAndQuery := strings.SplitN(c.Path, "?", 2)
	path := pathAndQuery[0]
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	if path[len(path)-1] != '/' {
		path += "/"
	}
	return path
}

func (c *SplitHTTPConfig) GetRequestHeader() http.Header {
	header := http.Header{}
	for k, vv := range c.Headers {
		for _, v := range vv {
			header.Add(k, v)
		}
	}
	applyDefaultFetchHeaders(header)
	return header
}

func applyDefaultFetchHeaders(header http.Header) {
	if header.Get("User-Agent") == "" {
		header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36")
	}
	if header.Get("Sec-CH-UA") == "" {
		header.Set("Sec-CH-UA", "\"Not=A?Brand\";v=\"8\", \"Chromium\";v=\"145\", \"Google Chrome\";v=\"145\"")
	}
	if header.Get("Sec-CH-UA-Mobile") == "" {
		header.Set("Sec-CH-UA-Mobile", "?0")
	}
	if header.Get("Sec-CH-UA-Platform") == "" {
		header.Set("Sec-CH-UA-Platform", "\"Windows\"")
	}
	if header.Get("DNT") == "" {
		header.Set("DNT", "1")
	}
	if header.Get("Accept-Language") == "" {
		header.Set("Accept-Language", "en-US,en;q=0.9")
	}
	if header.Get("Accept") == "" {
		header.Set("Accept", "*/*")
	}
	if header.Get("Cache-Control") == "" {
		header.Set("Cache-Control", "no-cache")
	}
	if header.Get("Pragma") == "" {
		header.Set("Pragma", "no-cache")
	}
	header.Set("Sec-Fetch-Mode", "cors")
	header.Set("Sec-Fetch-Dest", "empty")
	header.Set("Sec-Fetch-Site", "same-origin")
	if header.Get("Priority") == "" {
		header.Set("Priority", "u=1, i")
	}
}

func (c *SplitHTTPConfig) GetNormalizedXPaddingBytes() RangeConfig {
	if c.XPaddingBytes == nil || c.XPaddingBytes.To <= 0 {
		return RangeConfig{From: 100, To: 1000}
	}
	if c.XPaddingBytes.From <= 0 {
		return RangeConfig{From: 1, To: c.XPaddingBytes.To}
	}
	return *c.XPaddingBytes
}

func (c *SplitHTTPConfig) GetNormalizedUplinkHTTPMethod() string {
	if c.UplinkHTTPMethod == "" {
		return "POST"
	}
	return strings.ToUpper(c.UplinkHTTPMethod)
}

func (c *SplitHTTPConfig) GetNormalizedSessionPlacement() string {
	if c.SessionPlacement == "" {
		return PlacementPath
	}
	return c.SessionPlacement
}

func (c *SplitHTTPConfig) GetNormalizedSeqPlacement() string {
	if c.SeqPlacement == "" {
		return PlacementPath
	}
	return c.SeqPlacement
}

func (c *SplitHTTPConfig) GetNormalizedUplinkDataPlacement() string {
	if c.UplinkDataPlacement == "" {
		return PlacementBody
	}
	return c.UplinkDataPlacement
}

func (c *SplitHTTPConfig) GetNormalizedSessionKey() string {
	if c.SessionKey != "" {
		return c.SessionKey
	}
	switch c.GetNormalizedSessionPlacement() {
	case PlacementHeader:
		return "X-Session"
	case PlacementCookie, PlacementQuery:
		return "x_session"
	default:
		return ""
	}
}

func (c *SplitHTTPConfig) GetNormalizedSeqKey() string {
	if c.SeqKey != "" {
		return c.SeqKey
	}
	switch c.GetNormalizedSeqPlacement() {
	case PlacementHeader:
		return "X-Seq"
	case PlacementCookie, PlacementQuery:
		return "x_seq"
	default:
		return ""
	}
}

func (c *SplitHTTPConfig) GetNormalizedUplinkDataKey() string {
	if c.UplinkDataKey != "" {
		return c.UplinkDataKey
	}
	if c.GetNormalizedUplinkDataPlacement() == PlacementHeader {
		return "X-Data"
	}
	if c.GetNormalizedUplinkDataPlacement() == PlacementCookie {
		return "x_data"
	}
	return ""
}

func (c *SplitHTTPConfig) ExtractMetaFromRequest(req *http.Request, path string) (sessionID string, seqStr string) {
	sessionPlacement := c.GetNormalizedSessionPlacement()
	seqPlacement := c.GetNormalizedSeqPlacement()
	sessionKey := c.GetNormalizedSessionKey()
	seqKey := c.GetNormalizedSeqKey()

	var subpath []string
	pathPart := 0
	if sessionPlacement == PlacementPath || seqPlacement == PlacementPath {
		restPath := strings.TrimPrefix(req.URL.Path, path)
		restPath = strings.TrimPrefix(restPath, "/")
		if restPath != "" {
			subpath = strings.Split(restPath, "/")
		}
	}

	switch sessionPlacement {
	case PlacementPath:
		if len(subpath) > pathPart {
			sessionID = subpath[pathPart]
			pathPart++
		}
	case PlacementQuery:
		sessionID = req.URL.Query().Get(sessionKey)
	case PlacementHeader:
		sessionID = req.Header.Get(sessionKey)
	case PlacementCookie:
		if cookie, err := req.Cookie(sessionKey); err == nil {
			sessionID = cookie.Value
		}
	}

	switch seqPlacement {
	case PlacementPath:
		if len(subpath) > pathPart {
			seqStr = subpath[pathPart]
			pathPart++
		}
	case PlacementQuery:
		seqStr = req.URL.Query().Get(seqKey)
	case PlacementHeader:
		seqStr = req.Header.Get(seqKey)
	case PlacementCookie:
		if cookie, err := req.Cookie(seqKey); err == nil {
			seqStr = cookie.Value
		}
	}

	return sessionID, seqStr
}

func (c *SplitHTTPConfig) ApplyMetaToRequest(req *http.Request, sessionID string, seqStr string) {
	if sessionID != "" {
		switch c.GetNormalizedSessionPlacement() {
		case PlacementPath:
			req.URL.Path = appendToPath(req.URL.Path, sessionID)
		case PlacementQuery:
			q := req.URL.Query()
			q.Set(c.GetNormalizedSessionKey(), sessionID)
			req.URL.RawQuery = q.Encode()
		case PlacementHeader:
			req.Header.Set(c.GetNormalizedSessionKey(), sessionID)
		case PlacementCookie:
			req.AddCookie(&http.Cookie{Name: c.GetNormalizedSessionKey(), Value: sessionID})
		}
	}

	if seqStr != "" {
		switch c.GetNormalizedSeqPlacement() {
		case PlacementPath:
			req.URL.Path = appendToPath(req.URL.Path, seqStr)
		case PlacementQuery:
			q := req.URL.Query()
			q.Set(c.GetNormalizedSeqKey(), seqStr)
			req.URL.RawQuery = q.Encode()
		case PlacementHeader:
			req.Header.Set(c.GetNormalizedSeqKey(), seqStr)
		case PlacementCookie:
			req.AddCookie(&http.Cookie{Name: c.GetNormalizedSeqKey(), Value: seqStr})
		}
	}
}

func (c *SplitHTTPConfig) FillStreamRequest(req *http.Request, sessionID string) {
	req.Header = c.GetRequestHeader()
	length := randInRange(c.GetNormalizedXPaddingBytes())
	padding := XPaddingConfig{Length: length}
	if c.XPaddingObfsMode {
		padding.Placement = XPaddingPlacement{
			Placement: c.XPaddingPlacement,
			Key:       c.XPaddingKey,
			Header:    c.XPaddingHeader,
			RawURL:    req.URL.String(),
		}
		padding.Method = PaddingMethod(c.XPaddingMethod)
	} else {
		padding.Placement = XPaddingPlacement{
			Placement: PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    req.URL.String(),
		}
		padding.Method = PaddingMethodRepeatX
	}
	c.ApplyXPaddingToRequest(req, padding)
	c.ApplyMetaToRequest(req, sessionID, "")

	if req.Body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/grpc")
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Go-http-client/2.0")
	}
}

func (c *SplitHTTPConfig) FillPacketRequest(req *http.Request, sessionID string, seqStr string, payload []byte) {
	placement := c.GetNormalizedUplinkDataPlacement()
	if placement == PlacementBody || placement == PlacementAuto {
		req.Header = c.GetRequestHeader()
		req.Body = io.NopCloser(bytes.NewReader(payload))
		req.ContentLength = int64(len(payload))
	} else {
		req.Header = c.GetRequestHeader()
		s := encodePayload(payload)
		switch placement {
		case PlacementHeader:
			req.Header.Set(c.GetNormalizedUplinkDataKey()+"-0", s)
		case PlacementCookie:
			req.AddCookie(&http.Cookie{Name: c.GetNormalizedUplinkDataKey() + "_0", Value: s})
		}
	}

	length := randInRange(c.GetNormalizedXPaddingBytes())
	padding := XPaddingConfig{Length: length}
	if c.XPaddingObfsMode {
		padding.Placement = XPaddingPlacement{
			Placement: c.XPaddingPlacement,
			Key:       c.XPaddingKey,
			Header:    c.XPaddingHeader,
			RawURL:    req.URL.String(),
		}
		padding.Method = PaddingMethod(c.XPaddingMethod)
	} else {
		padding.Placement = XPaddingPlacement{
			Placement: PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    req.URL.String(),
		}
		padding.Method = PaddingMethodRepeatX
	}
	c.ApplyXPaddingToRequest(req, padding)
	c.ApplyMetaToRequest(req, sessionID, seqStr)

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Go-http-client/2.0")
	}
}

func encodePayload(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func (c *SplitHTTPConfig) HeaderSummary(req *http.Request) string {
	keys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(req.Header))
	for _, k := range keys {
		vv := req.Header[k]
		parts = append(parts, k+"="+strings.Join(vv, "|"))
	}
	return strings.Join(parts, ";")
}

func (c *SplitHTTPConfig) MetaSummary(req *http.Request) string {
	return "sessionPlacement=" + c.GetNormalizedSessionPlacement() + ",seqPlacement=" + c.GetNormalizedSeqPlacement() + ",uplinkDataPlacement=" + c.GetNormalizedUplinkDataPlacement() + ",path=" + req.URL.Path + ",query=" + req.URL.RawQuery + ",contentLength=" + strconv.FormatInt(req.ContentLength, 10)
}
