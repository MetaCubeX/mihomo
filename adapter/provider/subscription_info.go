package provider

import (
	"strconv"
	"strings"
)

type SubscriptionInfo struct {
	Upload   int64
	Download int64
	Total    int64
	Expire   int64
}

func NewSubscriptionInfo(userinfo string) (si *SubscriptionInfo, err error) {
	userinfo = strings.ToLower(userinfo)
	userinfo = strings.ReplaceAll(userinfo, " ", "")
	si = new(SubscriptionInfo)
	for _, field := range strings.Split(userinfo, ";") {
		switch name, value, _ := strings.Cut(field, "="); name {
		case "upload":
			si.Upload, err = strconv.ParseInt(value, 10, 64)
		case "download":
			si.Download, err = strconv.ParseInt(value, 10, 64)
		case "total":
			si.Total, err = strconv.ParseInt(value, 10, 64)
		case "expire":
			if value == "" {
				si.Expire = 0
			} else {
				si.Expire, err = strconv.ParseInt(value, 10, 64)
			}
		}
		if err != nil {
			return
		}
	}
	return
}
