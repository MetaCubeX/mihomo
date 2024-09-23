package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"gopkg.in/yaml.v3"
)

var tunnel P.Tunnel

func SetTunnel(t P.Tunnel) {
	tunnel = t
}

type ruleSetProvider struct {
	*resource.Fetcher[ruleStrategy]
	behavior P.RuleBehavior
	format   P.RuleFormat
	strategy ruleStrategy
}

type RuleSetProvider struct {
	*ruleSetProvider
}

type RulePayload struct {
	/**
	key: Domain or IP Cidr
	value: Rule type or is empty
	*/
	Payload []string `yaml:"payload"`
	Rules   []string `yaml:"rules"`
}

type ruleStrategy interface {
	Behavior() P.RuleBehavior
	Match(metadata *C.Metadata) bool
	Count() int
	ShouldResolveIP() bool
	ShouldFindProcess() bool
	Reset()
	Insert(rule string)
	FinishInsert()
}

type mrsRuleStrategy interface {
	ruleStrategy
	FromMrs(r io.Reader, count int) error
	WriteMrs(w io.Writer) error
	DumpMrs(f func(key string) bool)
}

func (rp *ruleSetProvider) Type() P.ProviderType {
	return P.Rule
}

func (rp *ruleSetProvider) Initial() error {
	_, err := rp.Fetcher.Initial()
	return err
}

func (rp *ruleSetProvider) Update() error {
	_, _, err := rp.Fetcher.Update()
	return err
}

func (rp *ruleSetProvider) Behavior() P.RuleBehavior {
	return rp.behavior
}

func (rp *ruleSetProvider) Count() int {
	return rp.strategy.Count()
}

func (rp *ruleSetProvider) Match(metadata *C.Metadata) bool {
	return rp.strategy != nil && rp.strategy.Match(metadata)
}

func (rp *ruleSetProvider) ShouldResolveIP() bool {
	return rp.strategy.ShouldResolveIP()
}

func (rp *ruleSetProvider) ShouldFindProcess() bool {
	return rp.strategy.ShouldFindProcess()
}

func (rp *ruleSetProvider) Strategy() any {
	return rp.strategy
}

func (rp *ruleSetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		map[string]interface{}{
			"behavior":    rp.behavior.String(),
			"format":      rp.format.String(),
			"name":        rp.Name(),
			"ruleCount":   rp.strategy.Count(),
			"type":        rp.Type().String(),
			"updatedAt":   rp.UpdatedAt(),
			"vehicleType": rp.VehicleType().String(),
		})
}

func (rp *RuleSetProvider) Close() error {
	runtime.SetFinalizer(rp, nil)
	return rp.ruleSetProvider.Close()
}

func NewRuleSetProvider(name string, behavior P.RuleBehavior, format P.RuleFormat, interval time.Duration, vehicle P.Vehicle,
	parse func(tp, payload, target string, params []string, subRules map[string][]C.Rule) (parsed C.Rule, parseErr error)) P.RuleProvider {
	rp := &ruleSetProvider{
		behavior: behavior,
		format:   format,
	}

	onUpdate := func(strategy ruleStrategy) {
		rp.strategy = strategy
		tunnel.RuleUpdateCallback().Emit(rp)
	}

	rp.strategy = newStrategy(behavior, parse)
	rp.Fetcher = resource.NewFetcher(name, interval, vehicle, func(bytes []byte) (ruleStrategy, error) {
		return rulesParse(bytes, newStrategy(behavior, parse), format)
	}, onUpdate)

	wrapper := &RuleSetProvider{
		rp,
	}

	runtime.SetFinalizer(wrapper, (*RuleSetProvider).Close)
	return wrapper
}

func newStrategy(behavior P.RuleBehavior, parse func(tp, payload, target string, params []string, subRules map[string][]C.Rule) (parsed C.Rule, parseErr error)) ruleStrategy {
	switch behavior {
	case P.Domain:
		strategy := NewDomainStrategy()
		return strategy
	case P.IPCIDR:
		strategy := NewIPCidrStrategy()
		return strategy
	case P.Classical:
		strategy := NewClassicalStrategy(parse)
		return strategy
	default:
		return nil
	}
}

var ErrNoPayload = errors.New("file must have a `payload` field")
var ErrInvalidFormat = errors.New("invalid format")

func rulesParse(buf []byte, strategy ruleStrategy, format P.RuleFormat) (ruleStrategy, error) {
	strategy.Reset()
	if format == P.MrsRule {
		return rulesMrsParse(buf, strategy)
	}

	schema := &RulePayload{}

	firstLineBuffer := pool.GetBuffer()
	defer pool.PutBuffer(firstLineBuffer)
	firstLineLength := 0

	s := 0 // search start index
	for s < len(buf) {
		// search buffer for a new line.
		line := buf[s:]
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			i += s
			line = buf[s : i+1]
			s = i + 1
		} else {
			s = len(buf)                                      // stop loop in next step
			if firstLineLength == 0 && format == P.YamlRule { // no head or only one line body
				return nil, ErrNoPayload
			}
		}
		var str string
		switch format {
		case P.TextRule:
			str = string(line)
			str = strings.TrimSpace(str)
			if len(str) == 0 {
				continue
			}
			if str[0] == '#' { // comment
				continue
			}
			if strings.HasPrefix(str, "//") { // comment in Premium core
				continue
			}
		case P.YamlRule:
			trimLine := bytes.TrimSpace(line)
			if len(trimLine) == 0 {
				continue
			}
			if trimLine[0] == '#' { // comment
				continue
			}
			firstLineBuffer.Write(line)
			if firstLineLength == 0 { // find payload head
				firstLineLength = firstLineBuffer.Len()
				firstLineBuffer.WriteString("  - ''") // a test line

				err := yaml.Unmarshal(firstLineBuffer.Bytes(), schema)
				firstLineBuffer.Truncate(firstLineLength)
				if err == nil && (len(schema.Rules) > 0 || len(schema.Payload) > 0) { // found
					continue
				}

				// not found or err!=nil
				firstLineBuffer.Truncate(0)
				firstLineLength = 0
				continue
			}

			// parse payload body
			err := yaml.Unmarshal(firstLineBuffer.Bytes(), schema)
			firstLineBuffer.Truncate(firstLineLength)
			if err != nil {
				continue
			}

			if len(schema.Rules) > 0 {
				str = schema.Rules[0]
			}
			if len(schema.Payload) > 0 {
				str = schema.Payload[0]
			}
		default:
			return nil, ErrInvalidFormat
		}

		if str == "" {
			continue
		}

		strategy.Insert(str)
	}

	strategy.FinishInsert()

	return strategy, nil
}
