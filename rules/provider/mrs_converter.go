package provider

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/klauspost/compress/zstd"
)

func ConvertToMrs(buf []byte, behavior P.RuleBehavior, format P.RuleFormat, w io.Writer) (err error) {
	strategy := newStrategy(behavior, nil)
	strategy, err = rulesParse(buf, strategy, format)
	if err != nil {
		return err
	}
	if strategy.Count() == 0 {
		return errors.New("empty rule")
	}
	if _strategy, ok := strategy.(mrsRuleStrategy); ok {
		if format == P.MrsRule { // export to TextRule
			_strategy.DumpMrs(func(key string) bool {
				_, err = fmt.Fprintln(w, key)
				if err != nil {
					return false
				}
				return true
			})
			return nil
		}

		var encoder *zstd.Encoder
		encoder, err = zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
		if err != nil {
			return err
		}
		defer func() {
			zstdErr := encoder.Close()
			if err == nil {
				err = zstdErr
			}
		}()

		// header
		_, err = encoder.Write(MrsMagicBytes[:])
		if err != nil {
			return err
		}

		// behavior
		_behavior := []byte{behavior.Byte()}
		_, err = encoder.Write(_behavior[:])
		if err != nil {
			return err
		}

		// count
		count := int64(_strategy.Count())
		err = binary.Write(encoder, binary.BigEndian, count)
		if err != nil {
			return err
		}

		// extra (reserved for future using)
		var extra []byte
		err = binary.Write(encoder, binary.BigEndian, int64(len(extra)))
		if err != nil {
			return err
		}
		_, err = encoder.Write(extra)
		if err != nil {
			return err
		}

		return _strategy.WriteMrs(encoder)
	} else {
		return ErrInvalidFormat
	}
}

func ConvertMain(args []string) {
	if len(args) > 3 {
		behavior, err := P.ParseBehavior(args[0])
		if err != nil {
			panic(err)
		}
		format, err := P.ParseRuleFormat(args[1])
		if err != nil {
			panic(err)
		}
		source := args[2]
		target := args[3]

		sourceFile, err := os.ReadFile(source)
		if err != nil {
			panic(err)
		}

		targetFile, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			panic(err)
		}

		err = ConvertToMrs(sourceFile, behavior, format, targetFile)
		if err != nil {
			panic(err)
		}

		err = targetFile.Close()
		if err != nil {
			panic(err)
		}
	} else {
		panic("Usage: convert-ruleset <behavior> <format> <source file> <target file>")
	}
}
