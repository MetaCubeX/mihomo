package logic_test

import (
	// https://github.com/golang/go/wiki/CodeReviewComments#import-dot
	. "github.com/metacubex/mihomo/rules/logic"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules"
	"github.com/stretchr/testify/assert"
	"testing"
)

var ParseRule = rules.ParseRule

func TestAND(t *testing.T) {
	and, err := NewAND("((DOMAIN,baidu.com),(NETWORK,TCP),(DST-PORT,10001-65535))", "DIRECT", ParseRule)
	assert.Equal(t, nil, err)
	assert.Equal(t, "DIRECT", and.Adapter())
	assert.Equal(t, false, and.ShouldResolveIP())
	m, _ := and.Match(&C.Metadata{
		Host:    "baidu.com",
		NetWork: C.TCP,
		DstPort: 20000,
	})
	assert.Equal(t, true, m)

	and, err = NewAND("(DOMAIN,baidu.com),(NETWORK,TCP),(DST-PORT,10001-65535))", "DIRECT", ParseRule)
	assert.NotEqual(t, nil, err)

	and, err = NewAND("((AND,(DOMAIN,baidu.com),(NETWORK,TCP)),(NETWORK,TCP),(DST-PORT,10001-65535))", "DIRECT", ParseRule)
	assert.Equal(t, nil, err)
}

func TestNOT(t *testing.T) {
	not, err := NewNOT("((DST-PORT,6000-6500))", "REJECT", ParseRule)
	assert.Equal(t, nil, err)
	m, _ := not.Match(&C.Metadata{
		DstPort: 6100,
	})
	assert.Equal(t, false, m)

	_, err = NewNOT("((DST-PORT,5600-6666),(DOMAIN,baidu.com))", "DIRECT", ParseRule)
	assert.NotEqual(t, nil, err)

	_, err = NewNOT("(())", "DIRECT", ParseRule)
	assert.NotEqual(t, nil, err)
}

func TestOR(t *testing.T) {
	or, err := NewOR("((DOMAIN,baidu.com),(NETWORK,TCP),(DST-PORT,10001-65535))", "DIRECT", ParseRule)
	assert.Equal(t, nil, err)
	m, _ := or.Match(&C.Metadata{
		NetWork: C.TCP,
	})
	assert.Equal(t, true, m)
	assert.Equal(t, false, or.ShouldResolveIP())
}
