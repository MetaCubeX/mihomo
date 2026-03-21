package cmd

import (
	"fmt"
	"os/exec"
	"strings"
)

func ExecCmd(cmdStr string) (string, error) {
	args := splitArgs(cmdStr)

	var cmd *exec.Cmd
	if len(args) == 1 {
		cmd = exec.Command(args[0])
	} else {
		cmd = exec.Command(args[0], args[1:]...)

	}
	prepareBackgroundCommand(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v, %s", err, string(out))
	}
	return string(out), nil
}

func splitArgs(cmd string) []string {
	args := strings.Split(cmd, " ")

	// use in pipeline
	if len(args) > 2 && strings.ContainsAny(cmd, "|") {
		suffix := strings.Join(args[2:], " ")
		args = append(args[:2], suffix)
	}
	return args
}
