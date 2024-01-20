package common

import (
	"fmt"
	"strconv"

	C "github.com/metacubex/mihomo/constant"
)

type DSCP struct {
	*Base
	dscp    uint8
	payload string
	adapter string
}

func (d *DSCP) RuleType() C.RuleType {
	return C.DSCP
}

func (d *DSCP) Match(metadata *C.Metadata) (bool, string) {
	return metadata.DSCP == d.dscp, d.adapter
}

func (d *DSCP) Adapter() string {
	return d.adapter
}

func (d *DSCP) Payload() string {
	return d.payload
}

func NewDSCP(dscp string, adapter string) (*DSCP, error) {
	dscpi, err := strconv.Atoi(dscp)
	if err != nil {
		return nil, fmt.Errorf("parse DSCP rule fail: %w", err)
	}
	if dscpi < 0 || dscpi > 63 {
		return nil, fmt.Errorf("DSCP couldn't be negative or exceed 63")
	}
	return &DSCP{
		Base:    &Base{},
		payload: dscp,
		dscp:    uint8(dscpi),
		adapter: adapter,
	}, nil
}
