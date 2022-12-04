package listener

import (
	"fmt"
	"strings"

	"github.com/Dreamacro/clash/common/structure"
	C "github.com/Dreamacro/clash/constant"
	IN "github.com/Dreamacro/clash/listener/inbound"
)

var keyReplacer = strings.NewReplacer("_", "-")

func ParseListener(mapping map[string]any) (C.NewListener, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "inbound", WeaklyTypedInput: true, KeyReplacer: keyReplacer})
	proxyType, existType := mapping["type"].(string)
	if !existType {
		return nil, fmt.Errorf("missing type")
	}

	var (
		listener C.NewListener
		err      error
	)
	switch proxyType {
	case "socks":
		socksOption := &IN.SocksOption{}
		decoder.Decode(mapping, socksOption)
		listener, err = IN.NewSocks(socksOption)
	case "http":
		httpOption := &IN.HTTPOption{}
		decoder.Decode(mapping, httpOption)
		listener, err = IN.NewHTTP(httpOption)
	case "tproxy":
		tproxyOption := &IN.TProxyOption{}
		decoder.Decode(mapping, tproxyOption)
		listener, err = IN.NewTProxy(tproxyOption)
	case "redir":
		redirOption := &IN.RedirOption{}
		decoder.Decode(mapping, redirOption)
		listener, err = IN.NewRedir(redirOption)
	case "mixed":
		mixedOption := &IN.MixedOption{}
		decoder.Decode(mapping, mixedOption)
		listener, err = IN.NewMixed(mixedOption)
	default:
		return nil, fmt.Errorf("unsupport proxy type: %s", proxyType)
	}
	return listener, err
}
