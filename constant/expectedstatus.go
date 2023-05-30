package constant

import (
	"errors"
	"fmt"
	"github.com/Dreamacro/clash/common/utils"
	"strconv"
	"strings"
)

type ExpectedStatusRange = []utils.Range[uint16]

var errExpectedStatus = errors.New("expectedStatus error")

func NewExpectedStatus(expected string) (ExpectedStatusRange, error) {
	// example: 200 or 200/302 or 200-400 or 200/204/401-429/501-503
	expected = strings.TrimSpace(expected)
	if len(expected) == 0 || expected == "*" {
		return nil, nil
	}

	statusList := strings.Split(expected, "/")
	if len(statusList) > 28 {
		return nil, fmt.Errorf("%s, too many status to use, maximum support 28 status", errExpectedStatus.Error())
	}

	var statusRanges ExpectedStatusRange
	for _, s := range statusList {
		if s == "" {
			continue
		}

		status := strings.Split(s, "-")
		statusLen := len(status)
		if statusLen > 2 {
			return nil, errExpectedStatus
		}

		statusStart, err := strconv.ParseInt(strings.Trim(status[0], "[ ]"), 10, 32)
		if err != nil {
			return nil, errExpectedStatus
		}

		switch statusLen {
		case 1:
			statusRanges = append(statusRanges, *utils.NewRange(uint16(statusStart), uint16(statusStart)))
		case 2:
			statusEnd, err := strconv.ParseUint(strings.Trim(status[1], "[ ]"), 10, 32)
			if err != nil {
				return nil, errExpectedStatus
			}

			statusRanges = append(statusRanges, *utils.NewRange(uint16(statusStart), uint16(statusEnd)))
		}
	}

	if len(statusRanges) == 0 {
		return nil, errExpectedStatus
	}

	return statusRanges, nil
}

func CheckStatus(expectedStatus ExpectedStatusRange, status uint16) bool {
	if expectedStatus == nil || len(expectedStatus) == 0 {
		return true
	}

	for _, segment := range expectedStatus {
		if segment.Contains(status) {
			return true
		}
	}

	return false
}