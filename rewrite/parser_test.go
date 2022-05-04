package rewrites

import (
	"regexp"
	"testing"

	"github.com/Dreamacro/clash/constant"

	"github.com/stretchr/testify/assert"
)

func TestParseRewrite(t *testing.T) {
	line0 := `^https?://example\.com/resource1/3/ url reject-dict`
	line1 := `^https?://example\.com/(resource2)/ url 307 https://example.com/new-$1`
	line2 := `^https?://example\.com/resource4/ url request-header (\r\n)User-Agent:.+(\r\n) request-header $1User-Agent: Fuck-Who$2`
	line3 := `should be error`

	c0, err0 := ParseRewrite(line0)
	c1, err1 := ParseRewrite(line1)
	c2, err2 := ParseRewrite(line2)
	_, err3 := ParseRewrite(line3)

	assert.NotNil(t, err3)

	assert.Nil(t, err0)
	assert.Equal(t, c0.RuleType(), constant.MitmRejectDict)

	assert.Nil(t, err1)
	assert.Equal(t, c1.RuleType(), constant.Mitm307)
	assert.Equal(t, c1.URLRegx(), regexp.MustCompile(`^https?://example\.com/(resource2)/`))
	assert.Equal(t, c1.RulePayload(), "https://example.com/new-$1")

	assert.Nil(t, err2)
	assert.Equal(t, c2.RuleType(), constant.MitmRequestHeader)
	assert.Equal(t, c2.RuleRegx(), regexp.MustCompile(`(\r\n)User-Agent:.+(\r\n)`))
	assert.Equal(t, c2.RulePayload(), "$1User-Agent: Fuck-Who$2")
}
