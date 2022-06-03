package logic

import (
	"github.com/Dreamacro/clash/constant"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAND(t *testing.T) {
	and, err := NewAND("((DOMAIN,baidu.com),(NETWORK,TCP),(DST-PORT,10001-65535))", "DIRECT")
	assert.Equal(t, nil, err)
	assert.Equal(t, "DIRECT", and.adapter)
	assert.Equal(t, false, and.ShouldResolveIP())
	assert.Equal(t, true, and.Match(&constant.Metadata{
		Host:     "baidu.com",
		AddrType: constant.AtypDomainName,
		NetWork:  constant.TCP,
		DstPort:  "20000",
	}))

	and, err = NewAND("(DOMAIN,baidu.com),(NETWORK,TCP),(DST-PORT,10001-65535))", "DIRECT")
	assert.NotEqual(t, nil, err)

	and, err = NewAND("((AND,(DOMAIN,baidu.com),(NETWORK,TCP)),(NETWORK,TCP),(DST-PORT,10001-65535))", "DIRECT")
	assert.Equal(t, nil, err)
}

func TestNOT(t *testing.T) {
	not, err := NewNOT("((DST-PORT,6000-6500))", "REJECT")
	assert.Equal(t, nil, err)
	assert.Equal(t, false, not.Match(&constant.Metadata{
		DstPort: "6100",
	}))

	_, err = NewNOT("((DST-PORT,5600-6666),(DOMAIN,baidu.com))", "DIRECT")
	assert.NotEqual(t, nil, err)

	_, err = NewNOT("(())", "DIRECT")
	assert.NotEqual(t, nil, err)
}

func TestOR(t *testing.T) {
	or, err := NewOR("((DOMAIN,baidu.com),(NETWORK,TCP),(DST-PORT,10001-65535))", "DIRECT")
	assert.Equal(t, nil, err)
	assert.Equal(t, true, or.Match(&constant.Metadata{
		NetWork: constant.TCP,
	}))
	assert.Equal(t, false, or.ShouldResolveIP())
}
