package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// jsonPathSegment is one segment of a simplified JSON path expression.
//
// A path is composed of key accesses separated by dots, where any
// segment may end with "[]" to iterate over an array and flatten its
// elements, e.g.:
//
//	prefixes[].ipv4Prefix  -> iterate the "prefixes" array and take "ipv4Prefix" of each element
//	actions[]              -> iterate the "actions" array and take its elements
//	[]                     -> iterate the root array
//	a.b                    -> nested object key access
type jsonPathSegment struct {
	key     string
	iterate bool
}

// parseJSONPath compiles a simplified JSON path expression into segments.
func parseJSONPath(path string) ([]jsonPathSegment, error) {
	p := strings.TrimSpace(path)
	p = strings.TrimPrefix(p, "$")
	p = strings.TrimPrefix(p, ".")
	if p == "" {
		return nil, fmt.Errorf("empty json path")
	}
	var segments []jsonPathSegment
	for _, raw := range strings.Split(p, ".") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return nil, fmt.Errorf("invalid json path %q: empty segment", path)
		}
		segment := jsonPathSegment{}
		if strings.HasSuffix(raw, "[]") {
			segment.iterate = true
			raw = strings.TrimSuffix(raw, "[]")
		}
		if strings.ContainsAny(raw, "[]") {
			return nil, fmt.Errorf("invalid json path %q: only the [] iteration is supported", path)
		}
		segment.key = raw
		segments = append(segments, segment)
	}
	return segments, nil
}

// appendJSONLeaves collects string leaves from a JSON value, flattening
// arrays automatically and ignoring null, boolean and object values.
func appendJSONLeaves(value any, rules *[]string) {
	switch v := value.(type) {
	case string:
		if s := strings.TrimSpace(v); s != "" {
			*rules = append(*rules, s)
		}
	case json.Number:
		*rules = append(*rules, v.String())
	case []any:
		for _, item := range v {
			appendJSONLeaves(item, rules)
		}
	default:
		// ignore nil, bool and map values
	}
}

// extractJSONRules walks the decoded JSON document with the compiled
// paths and returns every string leaf found, in order of appearance.
func extractJSONRules(root any, compiled [][]jsonPathSegment) []string {
	var rules []string
	for _, segments := range compiled {
		frontier := []any{root}
		for _, segment := range segments {
			next := make([]any, 0, len(frontier))
			for _, value := range frontier {
				if segment.key != "" {
					obj, ok := value.(map[string]any)
					if !ok {
						continue // missing field or non-object intermediate value
					}
					value = obj[segment.key]
				}
				if segment.iterate {
					arr, ok := value.([]any)
					if !ok {
						continue // not an array, ignore silently
					}
					next = append(next, arr...)
				} else {
					if segment.key == "" {
						continue
					}
					next = append(next, value)
				}
			}
			frontier = next
		}
		for _, value := range frontier {
			appendJSONLeaves(value, &rules)
		}
	}
	return rules
}

// rulesJSONParse decodes a JSON rule payload and inserts every string
// extracted by the configured paths into the strategy.
func rulesJSONParse(buf []byte, strategy ruleStrategy, paths []string) (ruleStrategy, error) {
	if len(paths) == 0 {
		return nil, errors.New("json format requires `json.paths` in rule-provider config")
	}
	compiled := make([][]jsonPathSegment, 0, len(paths))
	for _, path := range paths {
		segments, err := parseJSONPath(path)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, segments)
	}

	var root any
	decoder := json.NewDecoder(bytes.NewReader(buf))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("invalid json rule provider: %w", err)
	}

	rules := extractJSONRules(root, compiled)
	if len(rules) == 0 {
		return nil, errors.New("no rules extracted from json rule provider")
	}

	for _, rule := range rules {
		strategy.Insert(rule)
	}
	strategy.FinishInsert()

	return strategy, nil
}
