package provider

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"gopkg.in/yaml.v3"
	"io"
	"runtime"
	"time"

	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/resource"
	C "github.com/Dreamacro/clash/constant"
	P "github.com/Dreamacro/clash/constant/provider"
)

var (
	ruleProviders = map[string]P.RuleProvider{}
)

type ruleSetProvider struct {
	*resource.Fetcher[any]
	behavior P.RuleType
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
	Match(metadata *C.Metadata) bool
	Count() int
	ShouldResolveIP() bool
	ShouldFindProcess() bool
	Reset()
	Insert(rule string)
	FinishInsert()
}

func RuleProviders() map[string]P.RuleProvider {
	return ruleProviders
}

func SetRuleProvider(ruleProvider P.RuleProvider) {
	if ruleProvider != nil {
		ruleProviders[(ruleProvider).Name()] = ruleProvider
	}
}

func (rp *ruleSetProvider) Type() P.ProviderType {
	return P.Rule
}

func (rp *ruleSetProvider) Initial() error {
	elm, err := rp.Fetcher.Initial()
	if err != nil {
		return err
	}

	rp.OnUpdate(elm)
	return nil
}

func (rp *ruleSetProvider) Update() error {
	elm, same, err := rp.Fetcher.Update()
	if err == nil && !same {
		rp.OnUpdate(elm)
		return nil
	}

	return err
}

func (rp *ruleSetProvider) Behavior() P.RuleType {
	return rp.behavior
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

func (rp *ruleSetProvider) AsRule(adaptor string) C.Rule {
	panic("implement me")
}

func (rp *ruleSetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		map[string]interface{}{
			"behavior":    rp.behavior.String(),
			"name":        rp.Name(),
			"ruleCount":   rp.strategy.Count(),
			"type":        rp.Type().String(),
			"updatedAt":   rp.UpdatedAt,
			"vehicleType": rp.VehicleType().String(),
		})
}

func NewRuleSetProvider(name string, behavior P.RuleType, interval time.Duration, vehicle P.Vehicle,
	parse func(tp, payload, target string, params []string, subRules map[string][]C.Rule) (parsed C.Rule, parseErr error)) P.RuleProvider {
	rp := &ruleSetProvider{
		behavior: behavior,
	}

	onUpdate := func(elm interface{}) {
		strategy := elm.(ruleStrategy)
		rp.strategy = strategy
	}

	rp.strategy = newStrategy(behavior, parse)
	rp.Fetcher = resource.NewFetcher(name, interval, vehicle, func(bytes []byte) (any, error) { return rulesParse(bytes, newStrategy(behavior, parse)) }, onUpdate)

	wrapper := &RuleSetProvider{
		rp,
	}

	final := func(provider *RuleSetProvider) { _ = rp.Fetcher.Destroy() }
	runtime.SetFinalizer(wrapper, final)
	return wrapper
}

func newStrategy(behavior P.RuleType, parse func(tp, payload, target string, params []string, subRules map[string][]C.Rule) (parsed C.Rule, parseErr error)) ruleStrategy {
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

func rulesParse(buf []byte, strategy ruleStrategy) (any, error) {
	strategy.Reset()

	schema := &RulePayload{}

	reader := bufio.NewReader(bytes.NewReader(buf))

	firstLineBuffer := pool.GetBuffer()
	defer pool.PutBuffer(firstLineBuffer)
	firstLineLength := 0

	for {
		line, isPrefix, err := reader.ReadLine()
		if err != nil {
			if err == io.EOF {
				if firstLineLength == 0 { // find payload head
					return nil, ErrNoPayload
				}
				break
			}
			return nil, err
		}
		firstLineBuffer.Write(line) // need a copy because the returned buffer is only valid until the next call to ReadLine
		if isPrefix {
			// If the line was too long for the buffer then isPrefix is set and the
			// beginning of the line is returned. The rest of the line will be returned
			// from future calls.
			continue
		}
		if firstLineLength == 0 { // find payload head
			firstLineBuffer.WriteByte('\n')
			firstLineLength = firstLineBuffer.Len()
			firstLineBuffer.WriteString("  - ''") // a test line

			err = yaml.Unmarshal(firstLineBuffer.Bytes(), schema)
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
		err = yaml.Unmarshal(firstLineBuffer.Bytes(), schema)
		firstLineBuffer.Truncate(firstLineLength)
		if err != nil {
			continue
		}
		var str string
		if len(schema.Rules) > 0 {
			str = schema.Rules[0]
		}
		if len(schema.Payload) > 0 {
			str = schema.Payload[0]
		}
		if str == "" {
			continue
		}

		strategy.Insert(str)
	}

	strategy.FinishInsert()

	return strategy, nil
}
