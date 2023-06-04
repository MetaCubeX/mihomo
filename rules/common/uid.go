package common

import (
	"fmt"
	"runtime"

	"github.com/Dreamacro/clash/common/utils"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

type Uid struct {
	*Base
	uids    utils.IntRanges[uint32]
	oUid    string
	adapter string
}

func NewUid(oUid, adapter string) (*Uid, error) {
	if !(runtime.GOOS == "linux" || runtime.GOOS == "android") {
		return nil, fmt.Errorf("uid rule not support this platform")
	}

	uidRange, err := utils.NewIntRanges[uint32](oUid)
	if err != nil {
		return nil, fmt.Errorf("%w, %s", errPayload, err.Error())
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
	if metadata.Uid != 0 {
		if u.uids.Check(metadata.Uid) {
			return true, u.adapter
		}
	}
	log.Warnln("[UID] could not get uid from %s", metadata.String())
	return false, ""
}

func (u *Uid) Adapter() string {
	return u.adapter
}

func (u *Uid) Payload() string {
	return u.oUid
}

func (u *Uid) ShouldFindProcess() bool {
	return true
}
