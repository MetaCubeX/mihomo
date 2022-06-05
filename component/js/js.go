//go:build !no_script

package js

import (
	"github.com/Dreamacro/clash/log"
	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/console"
	"github.com/dop251/goja_nodejs/eventloop"
	"github.com/dop251/goja_nodejs/require"
)

func init() {
	logPrinter := console.RequireWithPrinter(&JsLog{})
	require.RegisterNativeModule("console", logPrinter)
	contextFuncLoader := newContext()
	require.RegisterNativeModule("context", contextFuncLoader)
}

func preSetting(rt *goja.Runtime) {
	registry := new(require.Registry)
	registry.Enable(rt)

	console.Enable(rt)
	enable(rt)
	eventloop.EnableConsole(true)
}

func getLoop() *eventloop.EventLoop {
	loop := eventloop.NewEventLoop(func(loop *eventloop.EventLoop) {
		loop.Run(func(runtime *goja.Runtime) {
			preSetting(runtime)
		})
	})

	return loop
}

func compiler(name, code string) (*goja.Program, error) {
	return goja.Compile(name, code, false)
}

func run(loop *eventloop.EventLoop, program *goja.Program, args map[string]any, callback func(any, error)) {
	loop.Run(func(runtime *goja.Runtime) {
		for k, v := range args {
			runtime.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))
			err := runtime.Set(k, v)
			if err != nil {
				log.Errorln("Args to script failed, %s", err.Error())
			}
		}

		v, err := runtime.RunProgram(program)
		if v == nil {
			callback(nil, err)
		} else {
			callback(v.Export(), err)
		}
	})
}
