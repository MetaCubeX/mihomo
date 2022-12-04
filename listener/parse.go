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
		err = decoder.Decode(mapping, socksOption)
		if err != nil {
			return nil, err
		}
		listener, err = IN.NewSocks(socksOption)
	case "http":
		httpOption := &IN.HTTPOption{}
		err = decoder.Decode(mapping, httpOption)
		if err != nil {
			return nil, err
		}
		listener, err = IN.NewHTTP(httpOption)
	case "tproxy":
		tproxyOption := &IN.TProxyOption{}
		err = decoder.Decode(mapping, tproxyOption)
		if err != nil {
			return nil, err
		}
		listener, err = IN.NewTProxy(tproxyOption)
	case "redir":
		redirOption := &IN.RedirOption{}
		err = decoder.Decode(mapping, redirOption)
		if err != nil {
			return nil, err
		}
		listener, err = IN.NewRedir(redirOption)
	case "mixed":
		mixedOption := &IN.MixedOption{}
		err = decoder.Decode(mapping, mixedOption)
		if err != nil {
			return nil, err
		}
		listener, err = IN.NewMixed(mixedOption)
	default:
		return nil, fmt.Errorf("unsupport proxy type: %s", proxyType)
	}
	return listener, err
}
