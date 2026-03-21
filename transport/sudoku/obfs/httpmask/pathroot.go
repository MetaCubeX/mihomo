package httpmask

import "strings"

// normalizePathRoot normalizes the configured path root into "/<segment>" form.
//
// It is intentionally strict: only a single path segment is allowed, consisting of
// [A-Za-z0-9_-]. Invalid inputs are treated as empty (disabled).
func normalizePathRoot(root string) string {
	root = strings.TrimSpace(root)
	root = strings.Trim(root, "/")
	if root == "" {
		return ""
	}
	for i := 0; i < len(root); i++ {
		c := root[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '_' || c == '-':
		default:
			return ""
		}
	}
	return "/" + root
}

func joinPathRoot(root, path string) string {
	root = normalizePathRoot(root)
	if root == "" {
		return path
	}
	if path == "" {
		return root
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return root + path
}

func stripPathRoot(root, fullPath string) (string, bool) {
	root = normalizePathRoot(root)
	if root == "" {
		return fullPath, true
	}
	if !strings.HasPrefix(fullPath, root+"/") {
		return "", false
	}
	return strings.TrimPrefix(fullPath, root), true
}
