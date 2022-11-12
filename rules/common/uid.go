package common

import (
	"fmt"
	"github.com/Dreamacro/clash/common/utils"
	"github.com/Dreamacro/clash/component/process"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"runtime"
	"strconv"
	"strings"
)

type Uid struct {
	*Base
	uids    []utils.Range[uint32]
	oUid    string
	adapter string
}

func NewUid(oUid, adapter string) (*Uid, error) {
	//if len(_uids) > 28 {
	//	return nil, fmt.Errorf("%s, too many uid to use, maximum support 28 uid", errPayload.Error())
	//}
	if !(runtime.GOOS == "linux" || runtime.GOOS == "android") {
		return nil, fmt.Errorf("uid rule not support this platform")
	}

	var uidRange []utils.Range[uint32]
	for _, u := range strings.Split(oUid, "/") {
		if u == "" {
			continue
		}

		subUids := strings.Split(u, "-")
		subUidsLen := len(subUids)
		if subUidsLen > 2 {
			return nil, errPayload
		}

		uidStart, err := strconv.ParseUint(strings.Trim(subUids[0], "[ ]"), 10, 32)
		if err != nil {
			return nil, errPayload
		}

		switch subUidsLen {
		case 1:
			uidRange = append(uidRange, *utils.NewRange(uint32(uidStart), uint32(uidStart)))
		case 2:
			uidEnd, err := strconv.ParseUint(strings.Trim(subUids[1], "[ ]"), 10, 32)
			if err != nil {
				return nil, errPayload
			}

			uidRange = append(uidRange, *utils.NewRange(uint32(uidStart), uint32(uidEnd)))
		}
	}

	if len(uidRange) == 0 {
		return nil, errPayload
	}
	return &Uid{
		Base:    &Base{},
		adapter: adapter,
		oUid:    oUid,
		uids:    uidRange,
	}, nil
}

func (u *Uid) RuleType() C.RuleType {
	return C.Uid
}

func (u *Uid) Match(metadata *C.Metadata) (bool, string) {
	srcPort, err := strconv.ParseUint(metadata.SrcPort, 10, 16)
	if err != nil {
		return false, ""
	}
	var uid *uint32
	if metadata.Uid != nil {
		uid = metadata.Uid
	} else if uid, err = process.FindUid(metadata.NetWork.String(), metadata.SrcIP, int(srcPort)); err == nil {
		metadata.Uid = uid
	} else {
		log.Warnln("[UID] could not get uid from %s", metadata.String())
		return false, ""
	}

	if uid != nil {
		for _, _uid := range u.uids {
			if _uid.Contains(*uid) {
				return true, u.adapter
			}
		}
	}
	return false, ""
}

func (u *Uid) Adapter() string {
	return u.adapter
}

func (u *Uid) Payload() string {
	return u.oUid
}
