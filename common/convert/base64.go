package convert

import (
	"encoding/base64"
	"fmt"
	"strings"
)

var (
	encRaw = base64.RawStdEncoding
	enc    = base64.StdEncoding
)

// DecodeBase64 try to decode content from the given bytes,
// which can be in base64.RawStdEncoding, base64.StdEncoding or just plaintext.
func DecodeBase64(buf []byte) []byte {
	result, err := tryDecodeBase64(buf)
	if err != nil {
		return buf
	}
	return result
}

func tryDecodeBase64(buf []byte) ([]byte, error) {
	dBuf := make([]byte, encRaw.DecodedLen(len(buf)))
	n, err := encRaw.Decode(dBuf, buf)
	if err != nil {
		n, err = enc.Decode(dBuf, buf)
		if err != nil {
			return nil, err
		}
	}
	return dBuf[:n], nil
}

func urlSafe(data string) string {
	return strings.NewReplacer("+", "-", "/", "_").Replace(data)
}

func decodeUrlSafe(data string) string {
	dcBuf, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	return string(dcBuf)
}

func TryDecodeBase64(s string) (decoded []byte, err error) {
	if len(s)%4 == 0 {
		if decoded, err = base64.StdEncoding.DecodeString(s); err == nil {
			return
		}
		if decoded, err = base64.URLEncoding.DecodeString(s); err == nil {
			return
		}
	} else {
		if decoded, err = base64.RawStdEncoding.DecodeString(s); err == nil {
			return
		}
		if decoded, err = base64.RawURLEncoding.DecodeString(s); err == nil {
			return
		}
	}
	return nil, fmt.Errorf("invalid base64-encoded string")
}
