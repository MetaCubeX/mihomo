//go:build !windows

package main

import (
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const stageVar = "__DAEMON_STAGE"

var logFilePath string

func getStage() (stage int, advanceStage func() error, resetEnv func() error) {
	var origValue string
	stage = 0

	daemonStage := os.Getenv(stageVar)
	stageTag := strings.SplitN(daemonStage, ":", 2)
	stageInfo := strings.SplitN(stageTag[0], "/", 3)

	if len(stageInfo) == 3 {
		stageStr, tm, check := stageInfo[0], stageInfo[1], stageInfo[2]

		hash := sha1.New()
		hash.Write([]byte(stageStr + "/" + tm + "/"))

		if check != hex.EncodeToString(hash.Sum([]byte{})) {
			origValue = daemonStage
		} else {
			stage, _ = strconv.Atoi(stageStr)

			if len(stageTag) == 2 {
				origValue = stageTag[1]
			}
		}
	} else {
		origValue = daemonStage
	}

	advanceStage = func() error {
		base := fmt.Sprintf("%d/%09d/", stage+1, time.Now().Nanosecond())
		hash := sha1.New()
		hash.Write([]byte(base))
		tag := base + hex.EncodeToString(hash.Sum([]byte{}))

		if err := os.Setenv(stageVar, tag+":"+origValue); err != nil {
			return fmt.Errorf("can't set %s: %s", stageVar, err)
		}
		return nil
	}
	resetEnv = func() error {
		return os.Setenv(stageVar, origValue)
	}

	return stage, advanceStage, resetEnv
}

func makeDaemon() error {
	stage, advanceStage, resetEnv := getStage()

	fatal := func(err error) error {
		if stage > 0 {
			os.Exit(1)
		}
		_ = resetEnv()
		return err
	}

	if stage < 2 {
		procName, err := os.Executable()
		if err != nil {
			return fatal(fmt.Errorf("can't determine full path to executable: %s", err))
		}
		if procName == "" {
			return fatal(fmt.Errorf("can't determine full path to executable"))
		}

		if err = advanceStage(); err != nil {
			return fatal(err)
		}
		dir, err := os.Getwd()
		if err != nil {
			return fatal(err)
		}
		files := []*os.File{os.Stdin, os.Stdout, os.Stderr}
		osAttrs := os.ProcAttr{Dir: dir, Env: os.Environ(), Files: files}

		if stage == 0 {
			osAttrs.Sys = &syscall.SysProcAttr{Setsid: true}
		}

		proc, err := os.StartProcess(procName, os.Args, &osAttrs)
		if err != nil {
			return fatal(fmt.Errorf("can't create process %s: %s", procName, err))
		}
		_ = proc.Release()
		os.Exit(0)
	}

	syscall.Umask(0)
	_ = resetEnv()

	return nil
}

func setLogFile(dir string) error {
	if logFilePath == "" {
		return nil
	}

	if f, err := os.Open(os.DevNull); err != nil {
		return err
	} else {
		err = unix.Dup2(int(f.Fd()), syscall.Stdin)
		_ = f.Close()
		if err != nil {
			return err
		}
	}

	lfPath := logFilePath
	if !filepath.IsAbs(lfPath) {
		lfPath = filepath.Join(dir, lfPath)
	}
	_ = os.MkdirAll(filepath.Dir(lfPath), 0755)

	lf, err := os.OpenFile(lfPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	defer func() { _ = lf.Close() }()

	fd := int(lf.Fd())
	if err = unix.Dup2(fd, syscall.Stdout); err != nil {
		return err
	}
	if err = unix.Dup2(fd, syscall.Stderr); err != nil {
		return err
	}

	return nil
}

func flagInit() {
	flag.BoolVar(&runDaemon, "daemon", false, "run in background")
	flag.StringVar(&logFilePath, "l", "", "log file path")
}
