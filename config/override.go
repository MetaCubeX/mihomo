package config

import (
	"dario.cat/mergo"
	"fmt"
	"github.com/metacubex/mihomo/log"
	"os"
	"os/user"
	"reflect"
	"runtime"
)

type ListMergeStrategy string

const (
	InsertFront ListMergeStrategy = "insert-front"
	Append      ListMergeStrategy = "append"
	Override    ListMergeStrategy = "override"
	Default     ListMergeStrategy = ""
)

// overrideTransformer is to merge slices with give strategy instead of the default behavior
// - insert-front: 	[old slice] -> [new slice, old slice]
// - append: 		[old slice] -> [old slice, new slice]
// - override: 		[old slice] -> [new slice] (Default)
type overrideTransformer struct {
	listStrategy ListMergeStrategy
}

func (t overrideTransformer) Transformer(typ reflect.Type) func(dst, src reflect.Value) error {
	if typ.Kind() == reflect.Slice {
		return func(dst, src reflect.Value) error {
			if src.IsNil() || !dst.CanSet() {
				return nil
			}
			if src.Kind() != reflect.Slice || dst.Kind() != reflect.Slice {
				return nil
			}
			// merge slice according to strategy
			switch t.listStrategy {
			case InsertFront:
				newSlice := reflect.AppendSlice(src, dst)
				dst.Set(newSlice)
			case Append:
				newSlice := reflect.AppendSlice(dst, src)
				dst.Set(newSlice)
			case Override, Default:
				dst.Set(src)
			default:
				return fmt.Errorf("unknown list override strategy: %s", t.listStrategy)
			}
			return nil
		}
	}
	return nil
}

func ApplyOverride(rawCfg *RawConfig, overrides []RawOverride) error {
	for id, override := range overrides {
		if override.OS != "" && override.OS != runtime.GOOS {
			continue
		}
		if override.Arch != "" && override.Arch != runtime.GOARCH {
			continue
		}
		if override.Hostname != "" {
			hName, err := os.Hostname()
			if err != nil {
				log.Warnln("Failed to get hostname when applying override #%v: %v", id, err)
				continue
			}
			if override.Hostname != hName {
				continue
			}
		}
		if override.Username != "" {
			u, err := user.Current()
			if err != nil {
				log.Warnln("Failed to get current user when applying override #%v: %v", id, err)
				continue
			}
			if override.Username != u.Username {
				continue
			}
		}

		// merge rawConfig override
		err := mergo.Merge(rawCfg, *override.Content, mergo.WithTransformers(overrideTransformer{
			listStrategy: override.ListStrategy,
		}), mergo.WithOverride)
		if err != nil {
			log.Errorln("Error when applying override #%v: %v", id, err)
		}
	}
	return nil
}
