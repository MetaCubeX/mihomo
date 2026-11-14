package log

import (
	"strings"
	"testing"
	"time"

	logrus "github.com/sirupsen/logrus"
)

func TestSetTimestamp(t *testing.T) {
	defer SetTimestamp(true)

	logger := logrus.StandardLogger()
	entry := &logrus.Entry{
		Logger:  logger,
		Time:    time.Date(2026, time.November, 7, 14, 2, 48, 0, time.UTC),
		Level:   logrus.InfoLevel,
		Message: "example message",
	}

	for _, tt := range []struct {
		name    string
		enabled bool
	}{
		{name: "enabled", enabled: true},
		{name: "disabled", enabled: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			SetTimestamp(tt.enabled)
			data, err := logger.Formatter.Format(entry)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(string(data), "time="); got != tt.enabled {
				t.Fatalf("timestamp present = %t, want %t: %s", got, tt.enabled, data)
			}
			if !strings.Contains(string(data), "example message") {
				t.Fatalf("message missing from formatted output: %s", data)
			}
		})
	}
}
