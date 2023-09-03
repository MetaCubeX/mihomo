package constant

import (
	"encoding/json"
	"errors"
	regexp "github.com/dlclark/regexp2"
)

var RewriteTypeMapping = map[string]RewriteType{
	MitmReject.String():         MitmReject,
	MitmReject200.String():      MitmReject200,
	MitmRejectImg.String():      MitmRejectImg,
	MitmRejectDict.String():     MitmRejectDict,
	MitmRejectArray.String():    MitmRejectArray,
	Mitm302.String():            Mitm302,
	Mitm307.String():            Mitm307,
	MitmRequestHeader.String():  MitmRequestHeader,
	MitmRequestBody.String():    MitmRequestBody,
	MitmResponseHeader.String(): MitmResponseHeader,
	MitmResponseBody.String():   MitmResponseBody,
}

const (
	MitmReject RewriteType = iota
	MitmReject200
	MitmRejectImg
	MitmRejectDict
	MitmRejectArray

	Mitm302
	Mitm307

	MitmRequestHeader
	MitmRequestBody

	MitmResponseHeader
	MitmResponseBody
)

type RewriteType int

// UnmarshalYAML unserialize RewriteType with yaml
func (e *RewriteType) UnmarshalYAML(unmarshal func(any) error) error {
	var tp string
	if err := unmarshal(&tp); err != nil {
		return err
	}
	mode, exist := RewriteTypeMapping[tp]
	if !exist {
		return errors.New("invalid MITM Action")
	}
	*e = mode
	return nil
}

// MarshalYAML serialize RewriteType with yaml
func (e RewriteType) MarshalYAML() (any, error) {
	return e.String(), nil
}

// UnmarshalJSON unserialize RewriteType with json
func (e *RewriteType) UnmarshalJSON(data []byte) error {
	var tp string
	json.Unmarshal(data, &tp)
	mode, exist := RewriteTypeMapping[tp]
	if !exist {
		return errors.New("invalid MITM Action")
	}
	*e = mode
	return nil
}

// MarshalJSON serialize RewriteType with json
func (e RewriteType) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

func (rt RewriteType) String() string {
	switch rt {
	case MitmReject:
		return "reject" // 404
	case MitmReject200:
		return "reject-200"
	case MitmRejectImg:
		return "reject-img"
	case MitmRejectDict:
		return "reject-dict"
	case MitmRejectArray:
		return "reject-array"
	case Mitm302:
		return "302"
	case Mitm307:
		return "307"
	case MitmRequestHeader:
		return "request-header"
	case MitmRequestBody:
		return "request-body"
	case MitmResponseHeader:
		return "response-header"
	case MitmResponseBody:
		return "response-body"
	default:
		return "Unknown"
	}
}

type Rewrite interface {
	ID() string
	URLRegx() *regexp.Regexp
	RuleType() RewriteType
	RuleRegx() *regexp.Regexp
	RulePayload() string
	ReplaceURLPayload([]string) string
	ReplaceSubPayload(string) string
}

type RewriteRule interface {
	SearchInRequest(func(Rewrite) bool) bool
	SearchInResponse(func(Rewrite) bool) bool
}
