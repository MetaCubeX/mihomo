package xhttp

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/common/utils"

	"github.com/metacubex/http"
	"github.com/metacubex/randv2"
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

type Config struct {
	Host                 string
	Path                 string
	Mode                 string
	Headers              map[string]string
	NoGRPCHeader         bool
	XPaddingBytes        string
	XPaddingObfsMode     bool
	XPaddingKey          string
	XPaddingHeader       string
	XPaddingPlacement    string
	XPaddingMethod       string
	UplinkHTTPMethod     string
	SessionPlacement     string
	SessionKey           string
	SessionTable         string // client only
	SessionLength        string // client only
	SeqPlacement         string
	SeqKey               string
	UplinkDataPlacement  string
	UplinkDataKey        string
	UplinkChunkSize      string
	NoSSEHeader          bool   // server only
	ScStreamUpServerSecs string // server only
	ScMaxBufferedPosts   string // server only
	ScMaxEachPostBytes   string
	ScMinPostsIntervalMs string
	ReuseConfig          *ReuseConfig
	DownloadConfig       *Config
}

type ReuseConfig struct {
	MaxConcurrency   string
	MaxConnections   string
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

func (c *Config) GetRequestHeader() http.Header {
	h := http.Header{}
	for k, v := range c.Headers {
		h.Set(k, v)
	}
	TryDefaultHeadersWith(h, "fetch")
	return h
}

func (c *Config) GetRequestHeaderWithPayload(payload []byte, uplinkChunkSize Range) http.Header {
	header := c.GetRequestHeader()

	key := c.UplinkDataKey
	encodedData := base64.RawURLEncoding.EncodeToString(payload)

	for i := 0; len(encodedData) > 0; i++ {
		chunkSize := uplinkChunkSize.Rand()
		if len(encodedData) < chunkSize {
			chunkSize = len(encodedData)
		}
		chunk := encodedData[:chunkSize]
		encodedData = encodedData[chunkSize:]
		headerKey := fmt.Sprintf("%s-%d", key, i)
		header.Set(headerKey, chunk)
	}

	return header
}

func (c *Config) GetRequestCookiesWithPayload(payload []byte, uplinkChunkSize Range) []*http.Cookie {
	cookies := []*http.Cookie{}

	key := c.UplinkDataKey
	encodedData := base64.RawURLEncoding.EncodeToString(payload)

	for i := 0; len(encodedData) > 0; i++ {
		chunkSize := uplinkChunkSize.Rand()
		if len(encodedData) < chunkSize {
			chunkSize = len(encodedData)
		}
		chunk := encodedData[:chunkSize]
		encodedData = encodedData[chunkSize:]
		cookieName := fmt.Sprintf("%s_%d", key, i)
		cookies = append(cookies, &http.Cookie{Name: cookieName, Value: chunk})
	}

	return cookies
}

func (c *Config) WriteResponseHeader(writer http.ResponseWriter, requestMethod string, requestHeader http.Header) {
	if origin := requestHeader.Get("Origin"); origin == "" {
		writer.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		// Chrome says: The value of the 'Access-Control-Allow-Origin' header in the response must not be the wildcard '*' when the request's credentials mode is 'include'.
		writer.Header().Set("Access-Control-Allow-Origin", origin)
	}

	if c.GetNormalizedSessionPlacement() == PlacementCookie ||
		c.GetNormalizedSeqPlacement() == PlacementCookie ||
		c.XPaddingPlacement == PlacementCookie ||
		c.GetNormalizedUplinkDataPlacement() == PlacementCookie {
		writer.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	if requestMethod == "OPTIONS" {
		requestedMethod := requestHeader.Get("Access-Control-Request-Method")
		if requestedMethod != "" {
			writer.Header().Set("Access-Control-Allow-Methods", requestedMethod)
		} else {
			writer.Header().Set("Access-Control-Allow-Methods", "*")
		}

		requestedHeaders := requestHeader.Get("Access-Control-Request-Headers")
		if requestedHeaders == "" {
			writer.Header().Set("Access-Control-Allow-Headers", "*")
		} else {
			writer.Header().Set("Access-Control-Allow-Headers", requestedHeaders)
		}
	}
}

func (c *Config) GetNormalizedUplinkHTTPMethod() string {
	if c.UplinkHTTPMethod == "" {
		return "POST"
	}
	return c.UplinkHTTPMethod
}

func (c *Config) GetNormalizedScStreamUpServerSecs() (Range, error) {
	r, err := ParseRange(c.ScStreamUpServerSecs, "20-80")
	if err != nil {
		return Range{}, fmt.Errorf("invalid sc-stream-up-server-secs: %w", err)
	}
	return r, nil
}

func (c *Config) GetNormalizedScMaxBufferedPosts() (Range, error) {
	r, err := ParseRange(c.ScMaxBufferedPosts, "30")
	if err != nil {
		return Range{}, fmt.Errorf("invalid sc-max-buffered-posts: %w", err)
	}
	if r.Max == 0 {
		return Range{}, fmt.Errorf("invalid sc-max-buffered-posts: must be greater than zero")
	}
	return r, nil
}

func (c *Config) GetNormalizedScMaxEachPostBytes() (Range, error) {
	r, err := ParseRange(c.ScMaxEachPostBytes, "1000000")
	if err != nil {
		return Range{}, fmt.Errorf("invalid sc-max-each-post-bytes: %w", err)
	}
	if r.Max == 0 {
		return Range{}, fmt.Errorf("invalid sc-max-each-post-bytes: must be greater than zero")
	}
	return r, nil
}

func (c *Config) GetNormalizedScMinPostsIntervalMs() (Range, error) {
	r, err := ParseRange(c.ScMinPostsIntervalMs, "30")
	if err != nil {
		return Range{}, fmt.Errorf("invalid sc-min-posts-interval-ms: %w", err)
	}
	if r.Max == 0 {
		return Range{}, fmt.Errorf("invalid sc-min-posts-interval-ms: must be greater than zero")
	}
	return r, nil
}

func (c *Config) GetNormalizedUplinkChunkSize() (Range, error) {
	uplinkChunkSize, err := ParseRange(c.UplinkChunkSize, "")
	if err != nil {
		return Range{}, fmt.Errorf("invalid uplink-chunk-size: %w", err)
	}
	if uplinkChunkSize.Max == 0 {
		switch c.GetNormalizedUplinkDataPlacement() {
		case PlacementCookie:
			return Range{
				Min: 2 * 1024, // 2 KiB
				Max: 3 * 1024, // 3 KiB
			}, nil
		case PlacementHeader:
			return Range{
				Min: 3 * 1024, // 3 KiB
				Max: 4 * 1024, // 4 KiB
			}, nil
		default:
			return c.GetNormalizedScMaxEachPostBytes()
		}
	} else if uplinkChunkSize.Min < 64 {
		uplinkChunkSize.Min = 64
		if uplinkChunkSize.Max < 64 {
			uplinkChunkSize.Max = 64
		}
	}
	return uplinkChunkSize, nil
}

func (c *Config) GetNormalizedSessionPlacement() string {
	if c.SessionPlacement == "" {
		return PlacementPath
	}
	return c.SessionPlacement
}

func (c *Config) GetNormalizedSeqPlacement() string {
	if c.SeqPlacement == "" {
		return PlacementPath
	}
	return c.SeqPlacement
}

func (c *Config) GetNormalizedUplinkDataPlacement() string {
	if c.UplinkDataPlacement == "" {
		return PlacementBody
	}
	return c.UplinkDataPlacement
}

func (c *Config) GetNormalizedSessionKey() string {
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

func (c *Config) GetNormalizedSeqKey() string {
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

type Range struct {
	Min int
	Max int
}

func (r Range) Rand() int {
	if r.Min == r.Max {
		return r.Min
	}
	return r.Min + randv2.IntN(r.Max-r.Min+1)
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

	maxConcurrency, err := ParseRange(c.MaxConcurrency, "0")
	if err != nil {
		return Range{}, Range{}, fmt.Errorf("invalid max-concurrency: %w", err)
	}

	maxConnections, err := ParseRange(c.MaxConnections, "0")
	if err != nil {
		return Range{}, Range{}, fmt.Errorf("invalid max-connections: %w", err)
	}

	return maxConcurrency, maxConnections, nil
}

func (c *ReuseConfig) ResolveEntryConfig() (Range, Range, Range, error) {
	if c == nil {
		return Range{}, Range{}, Range{}, nil
	}

	cMaxReuseTimes, err := ParseRange(c.CMaxReuseTimes, "0")
	if err != nil {
		return Range{}, Range{}, Range{}, fmt.Errorf("invalid c-max-reuse-times: %w", err)
	}

	hMaxRequestTimes, err := ParseRange(c.HMaxRequestTimes, "0")
	if err != nil {
		return Range{}, Range{}, Range{}, fmt.Errorf("invalid h-max-request-times: %w", err)
	}

	hMaxReusableSecs, err := ParseRange(c.HMaxReusableSecs, "0")
	if err != nil {
		return Range{}, Range{}, Range{}, fmt.Errorf("invalid h-max-reusable-secs: %w", err)
	}

	return cMaxReuseTimes, hMaxRequestTimes, hMaxReusableSecs, nil
}

func appendToPath(path, value string) string {
	if strings.HasSuffix(path, "/") {
		return path + value
	}
	return path + "/" + value
}

func (c *Config) ApplyMetaToRequest(req *http.Request, sessionId string, seqStr string) {
	sessionPlacement := c.GetNormalizedSessionPlacement()
	seqPlacement := c.GetNormalizedSeqPlacement()
	sessionKey := c.GetNormalizedSessionKey()
	seqKey := c.GetNormalizedSeqKey()

	if sessionId != "" {
		switch sessionPlacement {
		case PlacementPath:
			req.URL.Path = appendToPath(req.URL.Path, sessionId)
		case PlacementQuery:
			q := req.URL.Query()
			q.Set(sessionKey, sessionId)
			req.URL.RawQuery = q.Encode()
		case PlacementHeader:
			req.Header.Set(sessionKey, sessionId)
		case PlacementCookie:
			req.AddCookie(&http.Cookie{Name: sessionKey, Value: sessionId})
		}
	}

	if seqStr != "" {
		switch seqPlacement {
		case PlacementPath:
			req.URL.Path = appendToPath(req.URL.Path, seqStr)
		case PlacementQuery:
			q := req.URL.Query()
			q.Set(seqKey, seqStr)
			req.URL.RawQuery = q.Encode()
		case PlacementHeader:
			req.Header.Set(seqKey, seqStr)
		case PlacementCookie:
			req.AddCookie(&http.Cookie{Name: seqKey, Value: seqStr})
		}
	}
}

func (c *Config) ExtractMetaFromRequest(req *http.Request, path string) (sessionId string, seqStr string) {
	sessionPlacement := c.GetNormalizedSessionPlacement()
	seqPlacement := c.GetNormalizedSeqPlacement()
	sessionKey := c.GetNormalizedSessionKey()
	seqKey := c.GetNormalizedSeqKey()

	var subpath []string
	pathPart := 0
	if sessionPlacement == PlacementPath || seqPlacement == PlacementPath {
		subpath = strings.Split(req.URL.Path[len(path):], "/")
	}

	switch sessionPlacement {
	case PlacementPath:
		if len(subpath) > pathPart {
			sessionId = subpath[pathPart]
			pathPart += 1
		}
	case PlacementQuery:
		sessionId = req.URL.Query().Get(sessionKey)
	case PlacementHeader:
		sessionId = req.Header.Get(sessionKey)
	case PlacementCookie:
		if cookie, e := req.Cookie(sessionKey); e == nil {
			sessionId = cookie.Value
		}
	}

	switch seqPlacement {
	case PlacementPath:
		if len(subpath) > pathPart {
			seqStr = subpath[pathPart]
			pathPart += 1
		}
	case PlacementQuery:
		seqStr = req.URL.Query().Get(seqKey)
	case PlacementHeader:
		seqStr = req.Header.Get(seqKey)
	case PlacementCookie:
		if cookie, e := req.Cookie(seqKey); e == nil {
			seqStr = cookie.Value
		}
	}

	return sessionId, seqStr
}

func (c *Config) FillStreamRequest(req *http.Request, sessionID string) error {
	req.Header = c.GetRequestHeader()
	xPaddingBytes, err := c.GetNormalizedXPaddingBytes()
	if err != nil {
		return err
	}
	length := xPaddingBytes.Rand()
	config := XPaddingConfig{Length: length}

	if c.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: c.XPaddingPlacement,
			Key:       c.XPaddingKey,
			Header:    c.XPaddingHeader,
			RawURL:    req.URL.String(),
		}
		config.Method = PaddingMethod(c.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    req.URL.String(),
		}
	}

	c.ApplyXPaddingToRequest(req, config)
	c.ApplyMetaToRequest(req, sessionID, "")

	if req.Body != nil && !c.NoGRPCHeader { // stream-up/one
		req.Header.Set("Content-Type", "application/grpc")
	}

	return nil
}

func (c *Config) FillDownloadRequest(req *http.Request, sessionID string) error {
	return c.FillStreamRequest(req, sessionID)
}

func (c *Config) FillPacketRequest(request *http.Request, sessionId string, seqStr string, data []byte) error {
	dataPlacement := c.GetNormalizedUplinkDataPlacement()

	if dataPlacement == PlacementBody || dataPlacement == PlacementAuto {
		request.Header = c.GetRequestHeader()
		request.Body = io.NopCloser(bytes.NewReader(data))
		request.ContentLength = int64(len(data))
	} else {
		request.Body = nil
		request.ContentLength = 0
		switch dataPlacement {
		case PlacementHeader:
			uplinkChunkSize, err := c.GetNormalizedUplinkChunkSize()
			if err != nil {
				return err
			}
			request.Header = c.GetRequestHeaderWithPayload(data, uplinkChunkSize)
		case PlacementCookie:
			request.Header = c.GetRequestHeader()
			uplinkChunkSize, err := c.GetNormalizedUplinkChunkSize()
			if err != nil {
				return err
			}
			for _, cookie := range c.GetRequestCookiesWithPayload(data, uplinkChunkSize) {
				request.AddCookie(cookie)
			}
		}
	}

	xPaddingBytes, err := c.GetNormalizedXPaddingBytes()
	if err != nil {
		return err
	}
	length := xPaddingBytes.Rand()
	config := XPaddingConfig{Length: length}

	if c.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: c.XPaddingPlacement,
			Key:       c.XPaddingKey,
			Header:    c.XPaddingHeader,
			RawURL:    request.URL.String(),
		}
		config.Method = PaddingMethod(c.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    request.URL.String(),
		}
	}

	c.ApplyXPaddingToRequest(request, config)
	c.ApplyMetaToRequest(request, sessionId, seqStr)

	return nil
}

func roomSize(tableSize int, min, max int) *big.Int {
	base := big.NewInt(int64(tableSize))
	sum := new(big.Int)
	term := new(big.Int)
	for k := min; k <= max; k++ {
		term.Exp(base, big.NewInt(int64(k)), nil)
		sum.Add(sum, term)
	}
	return sum
}

var predefinedTable = map[string]string{
	"ALPHABET": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"Alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"BASE36":   "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"Base62":   "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"HEX":      "0123456789ABCDEF",
	"alphabet": "abcdefghijklmnopqrstuvwxyz",
	"base36":   "0123456789abcdefghijklmnopqrstuvwxyz",
	"hex":      "0123456789abcdef",
	"number":   "0123456789",
}

func (c *Config) GetGenerateSessionID() (func() string, error) {
	sessionTable := c.SessionTable
	switch sessionTable {
	case "": // maintain compatibility with older versions
		return func() string {
			var b [16]byte
			_, _ = rand.Read(b[:])
			return hex.EncodeToString(b[:])
		}, nil
	case "uuid": // some people rely on the UUID format string, WTF???
		return func() string {
			return utils.NewUUIDV4().String()
		}, nil
	default: // https://github.com/XTLS/Xray-core/pull/6258
		if predefined, ok := predefinedTable[sessionTable]; ok {
			sessionTable = predefined
		}
		sessionLength, err := ParseRange(c.SessionLength, "16-32")
		if err != nil {
			return nil, fmt.Errorf("invalid session-length: %w", err)
		}
		room := roomSize(len(c.SessionTable), sessionLength.Min, sessionLength.Max)
		// 2.1B possiblities should be enough
		if room.Cmp(big.NewInt(2<<30)) < 0 {
			return nil, errors.New("session-table or session-length is too small")
		}
		if sessionLength.Min <= 0 {
			return nil, errors.New("session-length must be greater than 0")
		}
		for i := 0; i < len(sessionTable); i++ {
			if sessionTable[i] >= 0x80 {
				return nil, errors.New("session-table must contain only ASCII characters")
			}
		}
		return func() string {
			length := sessionLength.Rand()
			id := make([]byte, length)
			for i := range id {
				id[i] = sessionTable[randv2.N(len(sessionTable))]
			}
			return string(id)
		}, nil
	}
}
