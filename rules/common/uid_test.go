package common

import (
	"bytes"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"

	"github.com/sirupsen/logrus"
)

func TestUidMatchWarnings(t *testing.T) {
	uids, err := utils.NewUnsignedRanges[uint32]("1000")
	if err != nil {
		t.Fatal(err)
	}
	rule := &Uid{uids: uids, adapter: "REJECT"}
	var output bytes.Buffer
	previousOutput := logrus.StandardLogger().Out
	logrus.SetOutput(&output)
	t.Cleanup(func() { logrus.SetOutput(previousOutput) })

	for _, test := range []struct {
		name    string
		uid     uint32
		match   bool
		warning bool
	}{
		{"matching UID", 1000, true, false},
		{"different UID", 1001, false, false},
		{"unavailable UID", 0, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			output.Reset()
			metadata := &C.Metadata{Host: "example.com"}
			matched, adapter := rule.Match(metadata, C.RuleMatchHelper{
				FindProcess: func() { metadata.Uid = test.uid },
			})
			if matched != test.match || (matched && adapter != "REJECT") {
				t.Fatalf("Match = (%v, %q), want matching = %v", matched, adapter, test.match)
			}
			if warning := strings.Contains(output.String(), "could not get uid"); warning != test.warning {
				t.Errorf("warning = %v, want %v; output = %s", warning, test.warning, output.String())
			}
		})
	}
}
