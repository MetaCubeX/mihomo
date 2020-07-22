package protocol

import (
	"bytes"

	"github.com/Dreamacro/clash/component/ssr/tools"
)

func init() {
	register("auth_aes128_sha1", newAuthAES128SHA1)
}

func newAuthAES128SHA1(b *Base) Protocol {
	return &authAES128{
		Base:       b,
		recvInfo:   &recvInfo{buffer: new(bytes.Buffer)},
		authData:   &authData{},
		salt:       "auth_aes128_sha1",
		hmac:       tools.HmacSHA1,
		hashDigest: tools.SHA1Sum,
	}
}
