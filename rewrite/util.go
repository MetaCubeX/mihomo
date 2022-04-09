package rewrites

import (
	"strings"
)

var allowContentType = []string{
	"text/",
	"application/xhtml",
	"application/xml",
	"application/atom+xml",
	"application/json",
	"application/x-www-form-urlencoded",
}

func CanRewriteBody(contentLength int64, contentType string) bool {
	if contentLength <= 0 {
		return false
	}

	for _, v := range allowContentType {
		if strings.HasPrefix(contentType, v) {
			return true
		}
	}

	return false
}
