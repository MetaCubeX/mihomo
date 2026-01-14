package httpmask

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
	}
	accepts = []string{
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"application/json, text/plain, */*",
		"application/octet-stream",
		"*/*",
	}
	acceptLanguages = []string{
		"en-US,en;q=0.9",
		"en-GB,en;q=0.9",
		"zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
		"ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
		"de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
	}
	acceptEncodings = []string{
		"gzip, deflate, br",
		"gzip, deflate",
		"br, gzip, deflate",
	}
	paths = []string{
		"/api/v1/upload",
		"/data/sync",
		"/uploads/raw",
		"/api/report",
		"/feed/update",
		"/v2/events",
		"/v1/telemetry",
		"/session",
		"/stream",
		"/ws",
	}
	contentTypes = []string{
		"application/octet-stream",
		"application/x-protobuf",
		"application/json",
	}
)

var (
	rngPool = sync.Pool{
		New: func() interface{} {
			return rand.New(rand.NewSource(time.Now().UnixNano()))
		},
	}
	headerBufPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, 1024)
			return &b
		},
	}
)

// LooksLikeHTTPRequestStart reports whether peek4 looks like a supported HTTP/1.x request method prefix.
func LooksLikeHTTPRequestStart(peek4 []byte) bool {
	if len(peek4) < 4 {
		return false
	}
	// Common methods: "GET ", "POST", "HEAD", "PUT ", "OPTI" (OPTIONS), "PATC" (PATCH), "DELE" (DELETE)
	return bytes.Equal(peek4, []byte("GET ")) ||
		bytes.Equal(peek4, []byte("POST")) ||
		bytes.Equal(peek4, []byte("HEAD")) ||
		bytes.Equal(peek4, []byte("PUT ")) ||
		bytes.Equal(peek4, []byte("OPTI")) ||
		bytes.Equal(peek4, []byte("PATC")) ||
		bytes.Equal(peek4, []byte("DELE"))
}

func trimPortForHost(host string) string {
	if host == "" {
		return host
	}
	// Accept "example.com:443" / "1.2.3.4:443" / "[::1]:443"
	h, _, err := net.SplitHostPort(host)
	if err == nil && h != "" {
		return h
	}
	// If it's not in host:port form, keep as-is.
	return host
}

func appendCommonHeaders(buf []byte, host string, r *rand.Rand) []byte {
	ua := userAgents[r.Intn(len(userAgents))]
	accept := accepts[r.Intn(len(accepts))]
	lang := acceptLanguages[r.Intn(len(acceptLanguages))]
	enc := acceptEncodings[r.Intn(len(acceptEncodings))]

	buf = append(buf, "Host: "...)
	buf = append(buf, host...)
	buf = append(buf, "\r\nUser-Agent: "...)
	buf = append(buf, ua...)
	buf = append(buf, "\r\nAccept: "...)
	buf = append(buf, accept...)
	buf = append(buf, "\r\nAccept-Language: "...)
	buf = append(buf, lang...)
	buf = append(buf, "\r\nAccept-Encoding: "...)
	buf = append(buf, enc...)
	buf = append(buf, "\r\nConnection: keep-alive\r\n"...)

	// A couple of common cache headers; keep them static for simplicity.
	buf = append(buf, "Cache-Control: no-cache\r\nPragma: no-cache\r\n"...)
	return buf
}

// WriteRandomRequestHeader writes a plausible HTTP/1.1 request header as a mask.
func WriteRandomRequestHeader(w io.Writer, host string) error {
	return WriteRandomRequestHeaderWithPathRoot(w, host, "")
}

// WriteRandomRequestHeaderWithPathRoot is like WriteRandomRequestHeader but prefixes all paths with pathRoot.
// pathRoot must be a single segment (e.g. "aabbcc"); invalid inputs are treated as empty (disabled).
func WriteRandomRequestHeaderWithPathRoot(w io.Writer, host string, pathRoot string) error {
	// Get RNG from pool
	r := rngPool.Get().(*rand.Rand)
	defer rngPool.Put(r)

	path := joinPathRoot(pathRoot, paths[r.Intn(len(paths))])
	ctype := contentTypes[r.Intn(len(contentTypes))]

	// Use buffer pool
	bufPtr := headerBufPool.Get().(*[]byte)
	buf := *bufPtr
	buf = buf[:0]
	defer func() {
		if cap(buf) <= 4096 {
			*bufPtr = buf
			headerBufPool.Put(bufPtr)
		}
	}()

	// Weighted template selection. Keep a conservative default (POST w/ Content-Length),
	// but occasionally rotate to other realistic templates (e.g. WebSocket upgrade).
	switch r.Intn(10) {
	case 0, 1: // ~20% WebSocket-like upgrade
		hostNoPort := trimPortForHost(host)
		var keyBytes [16]byte
		for i := 0; i < len(keyBytes); i++ {
			keyBytes[i] = byte(r.Intn(256))
		}
		wsKey := base64.StdEncoding.EncodeToString(keyBytes[:])

		buf = append(buf, "GET "...)
		buf = append(buf, path...)
		buf = append(buf, " HTTP/1.1\r\n"...)
		buf = appendCommonHeaders(buf, host, r)
		buf = append(buf, "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "...)
		buf = append(buf, wsKey...)
		buf = append(buf, "\r\nOrigin: https://"...)
		buf = append(buf, hostNoPort...)
		buf = append(buf, "\r\n\r\n"...)
	default: // ~80% POST upload
		// Random Content-Length: 4KB–10MB. Small enough to look plausible, large enough
		// to justify long-lived writes on keep-alive connections.
		const minCL = int64(4 * 1024)
		const maxCL = int64(10 * 1024 * 1024)
		contentLength := minCL + r.Int63n(maxCL-minCL+1)

		buf = append(buf, "POST "...)
		buf = append(buf, path...)
		buf = append(buf, " HTTP/1.1\r\n"...)
		buf = appendCommonHeaders(buf, host, r)
		buf = append(buf, "Content-Type: "...)
		buf = append(buf, ctype...)
		buf = append(buf, "\r\nContent-Length: "...)
		buf = strconv.AppendInt(buf, contentLength, 10)
		// A couple of extra headers seen in real clients.
		if r.Intn(2) == 0 {
			buf = append(buf, "\r\nX-Requested-With: XMLHttpRequest"...)
		}
		if r.Intn(3) == 0 {
			buf = append(buf, "\r\nReferer: https://"...)
			buf = append(buf, trimPortForHost(host)...)
			buf = append(buf, "/"...)
		}
		buf = append(buf, "\r\n\r\n"...)
	}

	_, err := w.Write(buf)
	return err
}

// ConsumeHeader 读取并消耗 HTTP 头部，返回消耗的数据和剩余的 reader 数据
// 如果不是 POST 请求或格式严重错误，返回 error
func ConsumeHeader(r *bufio.Reader) ([]byte, error) {
	var consumed bytes.Buffer

	// 1. 读取请求行
	// Use ReadSlice to avoid allocation if line fits in buffer
	line, err := r.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	consumed.Write(line)

	// Basic method validation: accept common HTTP/1.x methods used by our masker.
	// Keep it strict enough to reject obvious garbage.
	switch {
	case bytes.HasPrefix(line, []byte("POST ")),
		bytes.HasPrefix(line, []byte("GET ")),
		bytes.HasPrefix(line, []byte("HEAD ")),
		bytes.HasPrefix(line, []byte("PUT ")),
		bytes.HasPrefix(line, []byte("DELETE ")),
		bytes.HasPrefix(line, []byte("OPTIONS ")),
		bytes.HasPrefix(line, []byte("PATCH ")):
	default:
		return consumed.Bytes(), fmt.Errorf("invalid method or garbage: %s", strings.TrimSpace(string(line)))
	}

	// 2. 循环读取头部，直到遇到空行
	for {
		line, err = r.ReadSlice('\n')
		if err != nil {
			return consumed.Bytes(), err
		}
		consumed.Write(line)

		// Check for empty line (\r\n or \n)
		// ReadSlice includes the delimiter
		n := len(line)
		if n == 2 && line[0] == '\r' && line[1] == '\n' {
			return consumed.Bytes(), nil
		}
		if n == 1 && line[0] == '\n' {
			return consumed.Bytes(), nil
		}
	}
}
