package rules

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
)

func TestParseProtocolRule(t *testing.T) {
	rule, err := ParseRule("PROTOCOL", "bittorrent", "REJECT", nil, nil)
	assert.NoError(t, err)
	assert.Equal(t, C.Protocol, rule.RuleType())
	assert.Equal(t, "bittorrent", rule.Payload())
	assert.Equal(t, "REJECT", rule.Adapter())

	// the name is normalized, a config written as PROTOCOL,BitTorrent works too
	rule, err = ParseRule("PROTOCOL", " BitTorrent ", "REJECT", nil, nil)
	assert.NoError(t, err)
	assert.Equal(t, "bittorrent", rule.Payload())

	// an undetectable protocol is a config error rather than a rule that can
	// never match
	_, err = ParseRule("PROTOCOL", "smtp", "REJECT", nil, nil)
	assert.Error(t, err)
}

func TestProtocolRuleMatch(t *testing.T) {
	rule, err := ParseRule("PROTOCOL", "bittorrent", "REJECT", nil, nil)
	assert.NoError(t, err)

	matched, adapter := rule.Match(&C.Metadata{SniffProtocol: C.ProtocolBitTorrent}, C.RuleMatchHelper{})
	assert.True(t, matched)
	assert.Equal(t, "REJECT", adapter)

	// nothing sniffed, or sniffed as something else, must not match
	matched, _ = rule.Match(&C.Metadata{}, C.RuleMatchHelper{})
	assert.False(t, matched)
	matched, _ = rule.Match(&C.Metadata{SniffProtocol: "quic"}, C.RuleMatchHelper{})
	assert.False(t, matched)
}

func TestProtocolRuleInLogicRule(t *testing.T) {
	rule, err := ParseRule("AND", "((PROTOCOL,bittorrent),(NETWORK,udp))", "REJECT", nil, nil)
	assert.NoError(t, err)

	matched, _ := rule.Match(&C.Metadata{
		NetWork:       C.UDP,
		SniffProtocol: C.ProtocolBitTorrent,
	}, C.RuleMatchHelper{})
	assert.True(t, matched)

	matched, _ = rule.Match(&C.Metadata{
		NetWork:       C.TCP,
		SniffProtocol: C.ProtocolBitTorrent,
	}, C.RuleMatchHelper{})
	assert.False(t, matched)
}
