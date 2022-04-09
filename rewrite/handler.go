package rewrites

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/mitm"
	"github.com/Dreamacro/clash/tunnel"
)

var _ mitm.Handler = (*RewriteHandler)(nil)

type RewriteHandler struct{}

func (*RewriteHandler) HandleRequest(session *mitm.Session) (*http.Request, *http.Response) {
	var (
		request  = session.Request()
		response *http.Response
	)

	rule, sub, found := matchRewriteRule(request.URL.String(), true)
	if !found {
		return nil, nil
	}

	switch rule.RuleType() {
	case C.MitmReject:
		response = session.NewResponse(http.StatusNotFound, nil)
		response.Header.Set("Content-Type", "text/html; charset=utf-8")
	case C.MitmReject200:
		response = session.NewResponse(http.StatusOK, nil)
		response.Header.Set("Content-Type", "text/html; charset=utf-8")
	case C.MitmRejectImg:
		response = session.NewResponse(http.StatusOK, OnePixelPNG.Body())
		response.Header.Set("Content-Type", "image/png")
		response.ContentLength = OnePixelPNG.ContentLength()
	case C.MitmRejectDict:
		response = session.NewResponse(http.StatusOK, EmptyDict.Body())
		response.Header.Set("Content-Type", "application/json; charset=utf-8")
		response.ContentLength = EmptyDict.ContentLength()
	case C.MitmRejectArray:
		response = session.NewResponse(http.StatusOK, EmptyArray.Body())
		response.Header.Set("Content-Type", "application/json; charset=utf-8")
		response.ContentLength = EmptyArray.ContentLength()
	case C.Mitm302:
		response = session.NewResponse(http.StatusFound, nil)
		response.Header.Set("Location", rule.ReplaceURLPayload(sub))
	case C.Mitm307:
		response = session.NewResponse(http.StatusTemporaryRedirect, nil)
		response.Header.Set("Location", rule.ReplaceURLPayload(sub))
	case C.MitmRequestHeader:
		if len(request.Header) == 0 {
			return nil, nil
		}

		rawHeader := &bytes.Buffer{}
		oldHeader := request.Header
		if err := oldHeader.Write(rawHeader); err != nil {
			return nil, nil
		}

		newRawHeader := rule.ReplaceSubPayload(rawHeader.String())
		tb := textproto.NewReader(bufio.NewReader(strings.NewReader(newRawHeader)))
		newHeader, err := tb.ReadMIMEHeader()
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, nil
		}
		request.Header = http.Header(newHeader)
	case C.MitmRequestBody:
		if !CanRewriteBody(request.ContentLength, request.Header.Get("Content-Type")) {
			return nil, nil
		}

		buf := make([]byte, request.ContentLength)
		_, err := io.ReadFull(request.Body, buf)
		if err != nil {
			return nil, nil
		}

		newBody := rule.ReplaceSubPayload(string(buf))
		request.Body = io.NopCloser(strings.NewReader(newBody))
		request.ContentLength = int64(len(newBody))
	default:
		found = false
	}

	if found {
		if response != nil {
			response.Close = true
		}
		return request, response
	}
	return nil, nil
}

func (*RewriteHandler) HandleResponse(session *mitm.Session) *http.Response {
	var (
		request  = session.Request()
		response = session.Response()
	)

	rule, _, found := matchRewriteRule(request.URL.String(), false)
	found = found && rule.RuleRegx() != nil
	if !found {
		return nil
	}

	switch rule.RuleType() {
	case C.MitmResponseHeader:
		if len(response.Header) == 0 {
			return nil
		}

		rawHeader := &bytes.Buffer{}
		oldHeader := response.Header
		if err := oldHeader.Write(rawHeader); err != nil {
			return nil
		}

		newRawHeader := rule.ReplaceSubPayload(rawHeader.String())
		tb := textproto.NewReader(bufio.NewReader(strings.NewReader(newRawHeader)))
		newHeader, err := tb.ReadMIMEHeader()
		if err != nil && !errors.Is(err, io.EOF) {
			return nil
		}

		response.Header = http.Header(newHeader)
		response.Header.Set("Content-Length", strconv.FormatInt(response.ContentLength, 10))
	case C.MitmResponseBody:
		if !CanRewriteBody(response.ContentLength, response.Header.Get("Content-Type")) {
			return nil
		}

		b, err := mitm.ReadDecompressedBody(response)
		_ = response.Body.Close()
		if err != nil {
			return nil
		}

		body, err := mitm.DecodeLatin1(bytes.NewReader(b))
		if err != nil {
			return nil
		}

		newBody := rule.ReplaceSubPayload(body)

		modifiedBody, err := mitm.EncodeLatin1(newBody)
		if err != nil {
			return nil
		}

		response.Body = ioutil.NopCloser(bytes.NewReader(modifiedBody))
		response.Header.Del("Content-Encoding")
		response.ContentLength = int64(len(modifiedBody))
	default:
		found = false
	}

	if found {
		return response
	}
	return nil
}

func (h *RewriteHandler) HandleApiRequest(*mitm.Session) bool {
	return false
}

// HandleError session maybe nil
func (h *RewriteHandler) HandleError(*mitm.Session, error) {}

func matchRewriteRule(url string, isRequest bool) (rr C.Rewrite, sub []string, found bool) {
	rewrites := tunnel.Rewrites()
	if isRequest {
		found = rewrites.SearchInRequest(func(r C.Rewrite) bool {
			sub = r.URLRegx().FindStringSubmatch(url)
			if len(sub) != 0 {
				rr = r
				return true
			}
			return false
		})
	} else {
		found = rewrites.SearchInResponse(func(r C.Rewrite) bool {
			if r.URLRegx().FindString(url) != "" {
				rr = r
				return true
			}
			return false
		})
	}

	return
}
