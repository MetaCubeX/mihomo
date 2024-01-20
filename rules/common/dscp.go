package common

import (
	"fmt"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

type DSCP struct {
	*Base
	ranges  utils.IntRanges[uint8]
	payload string
	adapter string
}

func (d *DSCP) RuleType() C.RuleType {
	return C.DSCP
}

func (d *DSCP) Match(metadata *C.Metadata) (bool, string) {
	return d.ranges.Check(metadata.DSCP), d.adapter
}

func (d *DSCP) Adapter() string {
	return d.adapter
}

func (d *DSCP) Payload() string {
	return d.payload
}

func NewDSCP(dscp string, adapter string) (*DSCP, error) {
	ranges, err := utils.NewUnsignedRanges[uint8](dscp)
	if err != nil {
		return nil, fmt.Errorf("parse DSCP rule fail: %w", err)
	}
	for _, r := range ranges {
		if r.End() > 63 {
			return nil, fmt.Errorf("DSCP couldn't be negative or exceed 63")
		}
	}
	return &DSCP{
		Base:    &Base{},
		payload: dscp,
		ranges:  ranges,
		adapter: adapter,
	}, nil
}
