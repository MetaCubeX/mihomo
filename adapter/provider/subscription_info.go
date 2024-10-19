package provider

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/log"
)

type SubscriptionInfo struct {
	Upload   int64
	Download int64
	Total    int64
	Expire   int64
}

func NewSubscriptionInfo(userinfo string) (si *SubscriptionInfo) {
	userinfo = strings.ReplaceAll(strings.ToLower(userinfo), " ", "")
	si = new(SubscriptionInfo)

	for _, field := range strings.Split(userinfo, ";") {
		name, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}

		intValue, err := parseValue(value)
		if err != nil {
			log.Warnln("[Provider] get subscription-userinfo: %e", err)
			continue
		}

		switch name {
		case "upload":
			si.Upload = intValue
		case "download":
			si.Download = intValue
		case "total":
			si.Total = intValue
		case "expire":
			si.Expire = intValue
		}
	}

	return si
}

func parseValue(value string) (int64, error) {
	if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
		return intValue, nil
	}

	if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
		return int64(floatValue), nil
	}

	return 0, fmt.Errorf("failed to parse value '%s'", value)
}
