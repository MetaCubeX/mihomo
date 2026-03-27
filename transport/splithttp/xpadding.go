package splithttp

import (
	"crypto/rand"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/http2/hpack"
)

const charsetBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
const avgHuffmanBytesPerCharBase62 = 0.8
const validationTolerance = 2

type XPaddingPlacement struct {
	Placement string
	Key       string
	Header    string
	RawURL    string
}

type XPaddingConfig struct {
	Length    int
	Placement XPaddingPlacement
	Method    PaddingMethod
}

func randInRange(r RangeConfig) int {
	if r.To <= 0 {
		return 0
	}
	min := r.From
	if min <= 0 {
		min = 1
	}
	max := r.To
	if max < min {
		max = min
	}
	delta := max - min + 1
	n, err := rand.Int(rand.Reader, big.NewInt(int64(delta)))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}

func randStringFromCharset(n int, charset string) (string, bool) {
	if n <= 0 || len(charset) == 0 {
		return "", false
	}
	m := len(charset)
	limit := byte(256 - (256 % m))
	result := make([]byte, n)
	i := 0
	buf := make([]byte, 256)
	for i < n {
		if _, err := rand.Read(buf); err != nil {
			return "", false
		}
		for _, rb := range buf {
			if rb >= limit {
				continue
			}
			result[i] = charset[int(rb)%m]
			i++
			if i == n {
				break
			}
		}
	}
	return string(result), true
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func generateTokenishPaddingBase62(targetHuffmanBytes int) string {
	n := int(math.Ceil(float64(targetHuffmanBytes) / avgHuffmanBytesPerCharBase62))
	if n < 1 {
		n = 1
	}
	randBase62Str, ok := randStringFromCharset(n, charsetBase62)
	if !ok {
		return ""
	}
	const maxIter = 150
	adjustChar := byte('X')
	for iter := 0; iter < maxIter; iter++ {
		currentLength := int(hpack.HuffmanEncodeLength(randBase62Str))
		diff := currentLength - targetHuffmanBytes
		if absInt(diff) <= validationTolerance {
			return randBase62Str
		}
		if diff < 0 {
			randBase62Str += string(adjustChar)
			if adjustChar == 'X' {
				adjustChar = 'Z'
			} else {
				adjustChar = 'X'
			}
		} else {
			if len(randBase62Str) <= 1 {
				return randBase62Str
			}
			randBase62Str = randBase62Str[:len(randBase62Str)-1]
		}
	}
	return randBase62Str
}

func generatePadding(method PaddingMethod, length int) string {
	if length <= 0 {
		return ""
	}
	switch method {
	case PaddingMethodTokenish:
		p := generateTokenishPaddingBase62(length)
		if p != "" {
			return p
		}
		return strings.Repeat("X", length)
	default:
		return strings.Repeat("X", length)
	}
}

func applyPaddingToCookie(req *http.Request, name, value string) {
	if req == nil || name == "" || value == "" {
		return
	}
	req.AddCookie(&http.Cookie{Name: name, Value: value, Path: "/"})
}

func applyPaddingToQuery(u *url.URL, key, value string) {
	if u == nil || key == "" || value == "" {
		return
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
}

func (c *SplitHTTPConfig) applyXPaddingToHeader(h http.Header, config XPaddingConfig) {
	if h == nil {
		return
	}
	paddingValue := generatePadding(config.Method, config.Length)
	switch p := config.Placement; p.Placement {
	case PlacementHeader:
		h.Set(p.Header, paddingValue)
	case PlacementQueryInHeader:
		u, err := url.Parse(p.RawURL)
		if err != nil || u == nil {
			return
		}
		u.RawQuery = p.Key + "=" + paddingValue
		h.Set(p.Header, u.String())
	}
}

func (c *SplitHTTPConfig) ApplyXPaddingToRequest(req *http.Request, config XPaddingConfig) {
	if req == nil {
		return
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	placement := config.Placement.Placement
	if placement == PlacementHeader || placement == PlacementQueryInHeader {
		c.applyXPaddingToHeader(req.Header, config)
		return
	}
	paddingValue := generatePadding(config.Method, config.Length)
	switch placement {
	case PlacementCookie:
		applyPaddingToCookie(req, config.Placement.Key, paddingValue)
	case PlacementQuery:
		applyPaddingToQuery(req.URL, config.Placement.Key, paddingValue)
	}
}
