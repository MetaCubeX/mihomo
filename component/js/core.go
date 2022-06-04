package js

import (
	"github.com/dop251/goja"
	"sync"
)

var JS sync.Map
var mux sync.Mutex

func NewJS(name, code string) error {
	program, err := compiler(name, code)
	if err != nil {
		return err
	}

	if _, ok := JS.Load(name); !ok {
		mux.Lock()
		defer mux.Unlock()
		if _, ok := JS.Load(name); !ok {
			JS.Store(name, program)
		}
	}

	return nil
}

func Run(name string, args map[string]any, callback func(any, error)) {
	if value, ok := JS.Load(name); ok {
		run(getLoop(), value.(*goja.Program), args, callback)
	}
}
