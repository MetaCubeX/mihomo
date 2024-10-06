package config

import (
	"github.com/metacubex/mihomo/log"
	"gopkg.in/yaml.v3"
	"os"
	"os/user"
	"runtime"
)

type ListMergeStrategy string

// insert-front: 	[old slice] -> [new slice, old slice]
// append: 			[old slice] -> [old slice, new slice]
// override: 		[old slice] -> [new slice] (Default)

const (
	InsertFront ListMergeStrategy = "insert-front"
	Append      ListMergeStrategy = "append"
	Override    ListMergeStrategy = "override"
	Default     ListMergeStrategy = ""
)

func ApplyOverride(rawCfg *RawConfig, overrides []RawOverride) error {
	for id, override := range overrides {
		// check override conditions
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

		// marshal override content back to text
		overrideContent, err := yaml.Marshal(override.Content)
		if err != nil {
			log.Errorln("Error when applying override #%v: %v", id, err)
			continue
		}

		// unmarshal override content into rawConfig, with custom list merge strategy
		switch override.ListStrategy {
		case Append:
			options := yaml.NewDecodeOptions().ListDecodeOption(yaml.ListDecodeAppend)
			err = yaml.UnmarshalWith(options, overrideContent, rawCfg)
		case InsertFront:
			options := yaml.NewDecodeOptions().ListDecodeOption(yaml.ListDecodeInsertFront)
			err = yaml.UnmarshalWith(options, overrideContent, rawCfg)
		case Override, Default:
			err = yaml.Unmarshal(overrideContent, rawCfg)
		default:
			log.Errorln("Bad list strategy in override #%v: %v", id, override.ListStrategy)
		}
		if err != nil {
			log.Errorln("Error when applying override #%v: %v", id, err)
			continue
		}
	}
	return nil
}
