package common

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"golang.org/x/net/idna"
)

// make sure the system has install related zoneinfo for local time zone!
func init() {
	log.Infoln("current system time is %s", time.Now().Format("2006-01-02 15:04:05"))
}

type Schedule struct {
	*Base
	weekDayArr  [7]bool
	startHour   int
	startMinute int
	endHour     int
	endMinute   int
	schedule    string
	adapter     string
}

func (d *Schedule) RuleType() C.RuleType {
	return C.Schedule
}

func (d *Schedule) Match(metadata *C.Metadata) (bool, string) {
	now := time.Now()
	//log.Infoln("system time is %", now.Format("2006-01-02 15:04:05.000 Mon Jan"))
	if d.weekDayArr[now.Weekday()] {
		startTime := time.Date(now.Year(), now.Month(), now.Day(), d.startHour, d.startMinute, 0, 0, now.Location())
		endTime := time.Date(now.Year(), now.Month(), now.Day(), d.endHour, d.endMinute, 59, 999999999, now.Location())
		if now.After(startTime) && now.Before(endTime) {
			//log.Infoln("src ip %s in the time %d:%d~%d:%d. adapter is %s.", metadata.SrcIP.String(), d.startHour, d.startMinute, d.endHour, d.endMinute, d.adapter)
			return true, d.adapter
		}
	}
	return false, d.adapter
}

func (d *Schedule) Adapter() string {
	return d.adapter
}

func (d *Schedule) Payload() string {
	return d.schedule
}

func NewSchedule(schedule string, adapter string) (*Schedule, error) {
	punycode, _ := idna.ToASCII(strings.ToUpper(schedule))
	weekDayArr := [7]bool{false, false, false, false, false, false, false}
	if len(punycode) != 19 {
		return nil, fmt.Errorf("could you initial Schedule rule %, the rule format is not correct!", punycode)
	}
	if punycode[0] == 'S' {
		weekDayArr[0] = true
	}
	if punycode[1] == 'M' {
		weekDayArr[1] = true
	}
	if punycode[2] == 'T' {
		weekDayArr[2] = true
	}
	if punycode[3] == 'W' {
		weekDayArr[3] = true
	}
	if punycode[4] == 'T' {
		weekDayArr[4] = true
	}
	if punycode[5] == 'F' {
		weekDayArr[5] = true
	}
	if punycode[6] == 'S' {
		weekDayArr[6] = true
	}
	startHour, err := strconv.Atoi(punycode[8:10])
	if err != nil {
		return nil, fmt.Errorf("could you initial Schedule rule %, the time format is not correct!", punycode)
	}
	startMinute, err := strconv.Atoi(punycode[11:13])
	if err != nil {
		return nil, fmt.Errorf("could you initial Schedule rule %, the time format is not correct!", punycode)
	}
	endHour, err := strconv.Atoi(punycode[14:16])
	if err != nil {
		return nil, fmt.Errorf("could you initial Schedule rule %, the time format is not correct!", punycode)
	}
	endMinute, err := strconv.Atoi(punycode[17:19])
	if err != nil {
		return nil, fmt.Errorf("could you initial Schedule rule %, the time format is not correct!", punycode)
	}
	if startHour > endHour {
		return nil, fmt.Errorf("could you initial Schedule rule %, the end time should not be earlier than start time s!", punycode)
	}
	if startHour == endHour && startMinute > endMinute {
		return nil, fmt.Errorf("could you initial Schedule rule %, the end time should not be earlier than start time s!", punycode)
	}
	return &Schedule{
		Base:        &Base{},
		weekDayArr:  weekDayArr,
		startHour:   startHour,
		startMinute: startMinute,
		endHour:     endHour,
		endMinute:   endMinute,
		schedule:    punycode,
		adapter:     adapter,
	}, nil
}

//var _ C.Rule = (*Schedule)(nil)
