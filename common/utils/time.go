package utils

import (
	"strconv"
	"time"
)

func ParseDuration(interval string, unit string) time.Duration {
	var Duration time.Duration
	switch unit {
	case "ms":
		_, err := strconv.Atoi(interval)
		if err == nil {
			interval += "ms"
		}
		Duration, _ = time.ParseDuration(interval)
	case "s":
		_, err := strconv.Atoi(interval)
		if err == nil {
			interval += "s"
		}
		Duration, _ = time.ParseDuration(interval)
	case "h":
		_, err := strconv.Atoi(interval)
		if err == nil {
			interval += "h"
		}
		Duration, _ = time.ParseDuration(interval)
	}
	return Duration
}
