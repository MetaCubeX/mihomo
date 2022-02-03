package rules

import (
	"fmt"
	"runtime"
	"strings"

	S "github.com/Dreamacro/clash/component/script"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

type Script struct {
	shortcut         string
	adapter          string
	shortcutFunction *S.PyObject
}

func (s *Script) RuleType() C.RuleType {
	return C.Script
}

func (s *Script) Match(metadata *C.Metadata) bool {
	rs, err := S.CallPyShortcut(s.shortcutFunction, metadata)
	if err != nil {
		log.Errorln("[Script] match rule error: %s", err.Error())
		return false
	}

	return rs
}

func (s *Script) Adapter() string {
	return s.adapter
}

func (s *Script) Payload() string {
	return s.shortcut
}

func (s *Script) ShouldResolveIP() bool {
	return false
}

func (s *Script) RuleExtra() *C.RuleExtra {
	return nil
}

func NewScript(shortcut string, adapter string) (*Script, error) {
	shortcut = strings.ToLower(shortcut)
	if !S.Py_IsInitialized() {
		return nil, fmt.Errorf("load script shortcut [%s] failure, can't find any shortcuts in the config file", shortcut)
	}

	shortcutFunction, err := S.LoadShortcutFunction(shortcut)
	if err != nil {
		return nil, fmt.Errorf("can't find script shortcut [%s] in the config file", shortcut)
	}

	obj := &Script{
		shortcut:         shortcut,
		adapter:          adapter,
		shortcutFunction: shortcutFunction,
	}

	runtime.SetFinalizer(obj, func(s *Script) {
		s.shortcutFunction.Clear()
	})

	log.Infoln("Start initial script shortcut rule %s => %s", shortcut, adapter)

	return obj, nil
}
