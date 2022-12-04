package listener

import (
	"fmt"

	"github.com/Dreamacro/clash/common/structure"
	C "github.com/Dreamacro/clash/constant"
	IN "github.com/Dreamacro/clash/listener/inbound"
)

func ParseListener(mapping map[string]any) (C.InboundListener, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "inbound", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	proxyType, existType := mapping["type"].(string)
	if !existType {
		return nil, fmt.Errorf("missing type")
	}

	var (
		listener C.InboundListener
		err      error
	)
	switch proxyType {
	case "socks":
		socksOption := &IN.SocksOption{UDP: true}
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
		tproxyOption := &IN.TProxyOption{UDP: true}
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
		mixedOption := &IN.MixedOption{UDP: true}
		err = decoder.Decode(mapping, mixedOption)
		if err != nil {
			return nil, err
		}
		listener, err = IN.NewMixed(mixedOption)
	case "tuic":
		tuicOption := &IN.TuicOption{
			MaxIdleTime:           15000,
			AuthenticationTimeout: 1000,
			ALPN:                  []string{"h3"},
			MaxUdpRelayPacketSize: 1500,
		}
		err = decoder.Decode(mapping, tuicOption)
		if err != nil {
			return nil, err
		}
		listener, err = IN.NewTuic(tuicOption)
	default:
		return nil, fmt.Errorf("unsupport proxy type: %s", proxyType)
	}
	return listener, err
}
