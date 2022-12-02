package sing

import (
	"fmt"

	"github.com/Dreamacro/clash/log"

	L "github.com/sagernet/sing/common/logger"
)

type logger struct{}

func (l logger) Trace(args ...any) {
	log.Debugln(fmt.Sprint(args...))
}

func (l logger) Debug(args ...any) {
	log.Debugln(fmt.Sprint(args...))
}

func (l logger) Info(args ...any) {
	log.Infoln(fmt.Sprint(args...))
}

func (l logger) Warn(args ...any) {
	log.Warnln(fmt.Sprint(args...))
}

func (l logger) Error(args ...any) {
	log.Errorln(fmt.Sprint(args...))
}

func (l logger) Fatal(args ...any) {
	log.Fatalln(fmt.Sprint(args...))
}

func (l logger) Panic(args ...any) {
	log.Fatalln(fmt.Sprint(args...))
}

var Logger L.Logger = logger{}
