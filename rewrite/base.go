package rewrites

import (
	"bytes"
	"io"
	"io/ioutil"

	C "github.com/Dreamacro/clash/constant"
)

var (
	EmptyDict   = NewResponseBody([]byte("{}"))
	EmptyArray  = NewResponseBody([]byte("[]"))
	OnePixelPNG = NewResponseBody([]byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x11, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x62, 0x62, 0x60, 0x60, 0x60, 0x00, 0x04, 0x00, 0x00, 0xff, 0xff, 0x00, 0x0f, 0x00, 0x03, 0xfe, 0x8f, 0xeb, 0xcf, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82})
)

type Body interface {
	Body() io.ReadCloser
	ContentLength() int64
}

type ResponseBody struct {
	data   []byte
	length int64
}

func (r *ResponseBody) Body() io.ReadCloser {
	return ioutil.NopCloser(bytes.NewReader(r.data))
}

func (r *ResponseBody) ContentLength() int64 {
	return r.length
}

func NewResponseBody(data []byte) *ResponseBody {
	return &ResponseBody{
		data:   data,
		length: int64(len(data)),
	}
}

type RewriteRules struct {
	request  []C.Rewrite
	response []C.Rewrite
}

func (rr *RewriteRules) SearchInRequest(do func(C.Rewrite) bool) bool {
	for _, v := range rr.request {
		if do(v) {
			return true
		}
	}
	return false
}

func (rr *RewriteRules) SearchInResponse(do func(C.Rewrite) bool) bool {
	for _, v := range rr.response {
		if do(v) {
			return true
		}
	}
	return false
}

func NewRewriteRules(req []C.Rewrite, res []C.Rewrite) *RewriteRules {
	return &RewriteRules{
		request:  req,
		response: res,
	}
}

var _ C.RewriteRule = (*RewriteRules)(nil)
