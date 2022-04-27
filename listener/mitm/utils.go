package mitm

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

var (
	ErrInvalidResponse = errors.New("invalid response")
	ErrInvalidURL      = errors.New("invalid URL")
)

func NewResponse(code int, body io.Reader, req *http.Request) *http.Response {
	if body == nil {
		body = &bytes.Buffer{}
	}

	rc, ok := body.(io.ReadCloser)
	if !ok {
		rc = ioutil.NopCloser(body)
	}

	res := &http.Response{
		StatusCode: code,
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
		Body:       rc,
		Request:    req,
	}

	if req != nil {
		res.Close = req.Close
		res.Proto = req.Proto
		res.ProtoMajor = req.ProtoMajor
		res.ProtoMinor = req.ProtoMinor
	}

	return res
}

func NewErrorResponse(req *http.Request, err error) *http.Response {
	res := NewResponse(http.StatusBadGateway, nil, req)
	res.Close = true

	date := res.Header.Get("Date")
	if date == "" {
		date = time.Now().Format(http.TimeFormat)
	}

	w := fmt.Sprintf(`199 "clash" %q %q`, err.Error(), date)
	res.Header.Add("Warning", w)
	return res
}

func ReadDecompressedBody(res *http.Response) ([]byte, error) {
	rBody := res.Body
	if res.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(rBody)
		if err != nil {
			return nil, err
		}
		rBody = gzReader

		defer func(gzReader *gzip.Reader) {
			_ = gzReader.Close()
		}(gzReader)
	}
	return ioutil.ReadAll(rBody)
}

func DecodeLatin1(reader io.Reader) (string, error) {
	r := transform.NewReader(reader, charmap.ISO8859_1.NewDecoder())
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func EncodeLatin1(str string) ([]byte, error) {
	return charmap.ISO8859_1.NewEncoder().Bytes([]byte(str))
}
