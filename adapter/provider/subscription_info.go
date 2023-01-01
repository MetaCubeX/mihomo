package provider

import (
	"github.com/dlclark/regexp2"
	"strconv"
	"strings"
)

type SubscriptionInfo struct {
	Upload   int64
	Download int64
	Total    int64
	Expire   int64
}

func NewSubscriptionInfo(str string) (si *SubscriptionInfo, err error) {
	si = &SubscriptionInfo{}
	str = strings.ToLower(str)
	reTraffic := regexp2.MustCompile("upload=(\\d+); download=(\\d+); total=(\\d+)", 0)
	reExpire := regexp2.MustCompile("expire=(\\d+)", 0)

	match, err := reTraffic.FindStringMatch(str)
	if err != nil || match == nil {
		return nil, err
	}
	group := match.Groups()
	si.Upload, err = str2uint64(group[1].String())
	if err != nil {
		return nil, err
	}

	si.Download, err = str2uint64(group[2].String())
	if err != nil {
		return nil, err
	}

	si.Total, err = str2uint64(group[3].String())
	if err != nil {
		return nil, err
	}

	match, _ = reExpire.FindStringMatch(str)
	if match != nil {
		group = match.Groups()
		si.Expire, err = str2uint64(group[1].String())
		if err != nil {
			return nil, err
		}
	}

	return
}

func str2uint64(str string) (int64, error) {
	i, err := strconv.ParseInt(str, 10, 64)
	return i, err
}
