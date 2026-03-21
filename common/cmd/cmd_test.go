package cmd

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitArgs(t *testing.T) {
	args := splitArgs("ls")
	args1 := splitArgs("ls -la")
	args2 := splitArgs("bash -c ls")
	args3 := splitArgs("bash -c ls -lahF | grep 'cmd'")

	assert.Equal(t, 1, len(args))
	assert.Equal(t, 2, len(args1))
	assert.Equal(t, 3, len(args2))
	assert.Equal(t, 3, len(args3))
}

func TestExecCmd(t *testing.T) {
	if runtime.GOOS == "windows" {
		_, err := ExecCmd("cmd -c 'dir'")
		assert.Nil(t, err)
		return
	}

	_, err := ExecCmd("ls")
	_, err1 := ExecCmd("ls -la")
	_, err2 := ExecCmd("bash -c ls")
	_, err3 := ExecCmd("bash -c ls -la")
	_, err4 := ExecCmd("bash -c ls -la | grep 'cmd'")

	assert.Nil(t, err)
	assert.Nil(t, err1)
	assert.Nil(t, err2)
	assert.Nil(t, err3)
	assert.Nil(t, err4)
}
