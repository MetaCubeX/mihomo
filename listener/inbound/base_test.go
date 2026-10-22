package inbound

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
)

func TestBaseOptionSpecialFields(t *testing.T) {
	opt := &BaseOption{NameStr: "mp-0", SpecialMode: "global", SpecialFallbackProxy: "MP-0-group"}
	base, err := NewBase(opt)
	assert.NoError(t, err)

	md := C.Metadata{}
	for _, add := range base.Additions() {
		add(&md)
	}
	assert.Equal(t, "mp-0", md.InName)
	assert.Equal(t, "global", md.SpecialMode)
	assert.Equal(t, "MP-0-group", md.SpecialFallbackProxy)
}
