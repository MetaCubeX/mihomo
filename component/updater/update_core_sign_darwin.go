package updater

import (
	"fmt"
	"os/exec"
	"strings"
)

func signCoreFile(path string) error {
	output, err := exec.Command("/usr/bin/codesign", "--force", "--sign", "-", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("codesign %s: %w: %s", path, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func verifyCoreFile(path string) error {
	output, err := exec.Command("/usr/bin/codesign", "--verify", "--strict", "--verbose=2", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("codesign verify %s: %w: %s", path, err, strings.TrimSpace(string(output)))
	}
	return nil
}
