//go:build !darwin

package updater

func signCoreFile(_ string) error {
	return nil
}

func verifyCoreFile(_ string) error {
	return nil
}
