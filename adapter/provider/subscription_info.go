package provider

import (
	"github.com/dlclark/regexp2"
	"strconv"
	"strings"
)

type SubscriptionInfo struct {
	Upload   *int
	Download *int
	Total    *int
	Expire   *int
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
	tmp, err := strconv.Atoi(group[1].String())
	if err != nil {
		return nil, err
	}
	si.Upload = &tmp
	tmp, err = strconv.Atoi(group[2].String())
	if err != nil {
		return nil, err
	}
	si.Download = &tmp
	tmp, err = strconv.Atoi(group[3].String())
	if err != nil {
		return nil, err
	}
	si.Total = &tmp

	match, _ = reExpire.FindStringMatch(str)
	if match != nil {
		group = match.Groups()
		tmp, err = strconv.Atoi(group[1].String())
		if err != nil {
			return nil, err
		}
		si.Expire = &tmp
	}

	return
}
