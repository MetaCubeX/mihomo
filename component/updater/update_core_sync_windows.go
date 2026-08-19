package updater

// The staged file's writable handle is synced before it is explicitly closed.
// Windows does not support syncing directories, and reopening an executable
// after restoring a read-only mode can fail unnecessarily.
func syncFile(_ string) error {
	return nil
}

func syncDirectory(_ string) error {
	return nil
}
