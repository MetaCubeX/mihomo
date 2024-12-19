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
	ruleSetProviderBase
	*resource.Fetcher[ruleStrategy]
	format P.RuleFormat
}

type ruleSetProviderBase struct {
	behavior P.RuleBehavior
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

func (rp *ruleSetProviderBase) Type() P.ProviderType {
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

func (rp *ruleSetProviderBase) Behavior() P.RuleBehavior {
	return rp.behavior
}

func (rp *ruleSetProviderBase) Count() int {
	return rp.strategy.Count()
}

func (rp *ruleSetProviderBase) Match(metadata *C.Metadata) bool {
	return rp.strategy != nil && rp.strategy.Match(metadata)
}

func (rp *ruleSetProviderBase) ShouldResolveIP() bool {
	return rp.strategy.ShouldResolveIP()
}

func (rp *ruleSetProviderBase) ShouldFindProcess() bool {
	return rp.strategy.ShouldFindProcess()
}

func (rp *ruleSetProviderBase) Strategy() any {
	return rp.strategy
}

type providerForApi struct {
	Behavior    string    `json:"behavior"`
	Format      string    `json:"format"`
	Name        string    `json:"name"`
	RuleCount   int       `json:"ruleCount"`
	Type        string    `json:"type"`
	VehicleType string    `json:"vehicleType"`
	UpdatedAt   time.Time `json:"updatedAt"`
	Payload     []string  `json:"payload,omitempty"`
}

func (rp *ruleSetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		providerForApi{
			Behavior:    rp.behavior.String(),
			Format:      rp.format.String(),
			Name:        rp.Fetcher.Name(),
			RuleCount:   rp.strategy.Count(),
			Type:        rp.Type().String(),
			UpdatedAt:   rp.UpdatedAt(),
			VehicleType: rp.VehicleType().String(),
		})
}

func (rp *RuleSetProvider) Close() error {
	runtime.SetFinalizer(rp, nil)
	return rp.ruleSetProvider.Close()
}

func NewRuleSetProvider(name string, behavior P.RuleBehavior, format P.RuleFormat, interval time.Duration, vehicle P.Vehicle,
	parse parseRuleFunc,
) P.RuleProvider {
	rp := &ruleSetProvider{
		ruleSetProviderBase: ruleSetProviderBase{
			behavior: behavior,
		},
		format: format,
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

func newStrategy(behavior P.RuleBehavior, parse parseRuleFunc) ruleStrategy {
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

var (
	ErrNoPayload     = errors.New("file must have a `payload` field")
	ErrInvalidFormat = errors.New("invalid format")
)

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

func rulesParseInline(rs []string, strategy ruleStrategy) ruleStrategy {
	strategy.Reset()
	for _, r := range rs {
		if r != "" {
			strategy.Insert(r)
		}
	}
	strategy.FinishInsert()
	return strategy
}

type inlineProvider struct {
	ruleSetProviderBase
	name       string
	updateTime time.Time
	payload    []string
}

func (i *inlineProvider) Name() string {
	return i.name
}

func (i *inlineProvider) Initial() error {
	return nil
}

func (i *inlineProvider) Update() error {
	// make api update happy
	i.updateTime = time.Now()
	return nil
}

func (i *inlineProvider) VehicleType() P.VehicleType {
	return P.Inline
}

func (i *inlineProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		providerForApi{
			Behavior:    i.behavior.String(),
			Name:        i.Name(),
			RuleCount:   i.strategy.Count(),
			Type:        i.Type().String(),
			VehicleType: i.VehicleType().String(),
			UpdatedAt:   i.updateTime,
			Payload:     i.payload,
		})
}

func newInlineProvider(
	name string,
	behavior P.RuleBehavior,
	payload []string,
	parse parseRuleFunc,
) P.RuleProvider {
	rp := &inlineProvider{
		ruleSetProviderBase: ruleSetProviderBase{
			behavior: behavior,
			strategy: newStrategy(behavior, parse),
		},
		payload:    payload,
		name:       name,
		updateTime: time.Now(),
	}
	rp.strategy = rulesParseInline(payload, rp.strategy)
	return rp
}
