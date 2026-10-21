package inventory

import "path/filepath"

// RelativePath converts absolute paths to relative paths. Tests may replace it
// to exercise layouts on different volumes; replacements must be restored.
var RelativePath = filepath.Rel

// RelativeOrAbsolute keeps a relative path when possible. Both inputs must be
// absolute; callers still need to handle errors resolving their inputs.
func RelativeOrAbsolute(base, target string) string {
	if relative, err := RelativePath(base, target); err == nil {
		return relative
	}
	return filepath.Clean(target)
}
