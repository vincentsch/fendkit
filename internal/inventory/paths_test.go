package inventory

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestRelativeOrAbsolute(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "..", "dist", "release.zip")
	if got := RelativeOrAbsolute(base, target); got != filepath.Join("..", "dist", "release.zip") {
		t.Fatal(got)
	}
	previous := RelativePath
	RelativePath = func(string, string) (string, error) { return "", errors.New("different volumes") }
	t.Cleanup(func() { RelativePath = previous })
	target = filepath.Dir(target) + string(filepath.Separator) + "." + string(filepath.Separator) + "release.zip"
	if got := RelativeOrAbsolute(base, target); got != filepath.Clean(target) || !filepath.IsAbs(got) {
		t.Fatal(got)
	}
}
