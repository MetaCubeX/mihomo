//go:build !no_script

package js

import (
	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/console"
	"github.com/dop251/goja_nodejs/eventloop"
	"github.com/dop251/goja_nodejs/require"
)

func preSetting(rt *goja.Runtime) {
	registry := new(require.Registry)
	registry.Enable(rt)
	logPrinter := console.RequireWithPrinter(&JsLog{})
	require.RegisterNativeModule("console", logPrinter)
	console.Enable(rt)
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
	loop.RunOnLoop(func(runtime *goja.Runtime) {
		for k, v := range args {
			runtime.Set(k, v)
		}

		v, err := runtime.RunProgram(program)
		callback(v, err)
	})
}
