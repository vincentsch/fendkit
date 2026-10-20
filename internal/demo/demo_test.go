package demo

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEmbeddedFixtureIsCurrent(t *testing.T) {
	source := os.DirFS("../../testdata/wp-plugin")
	bundled, err := fs.Sub(assets, "data")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]bool{}
	for _, tree := range []fs.FS{source, bundled} {
		err := fs.WalkDir(tree, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			a, e := fs.ReadFile(source, path)
			if e != nil {
				return e
			}
			b, e := fs.ReadFile(bundled, path)
			if e != nil {
				return e
			}
			if !bytes.Equal(a, b) {
				t.Errorf("%s is stale; run go generate ./internal/demo", path)
			}
			files[path] = true
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(t.TempDir(), "example")
	if err := Copy(out); err != nil {
		t.Fatal(err)
	}
	for path := range files {
		a, _ := fs.ReadFile(source, path)
		b, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(path)))
		if err != nil || !bytes.Equal(a, b) {
			t.Fatalf("copy lost %s: %v", path, err)
		}
	}
}

func TestSupportEndUsesValidCalendarDate(t *testing.T) {
	for _, tc := range []struct{ today, want string }{{"2028-02-29", "2033-02-28"}, {"2026-10-20", "2031-10-20"}} {
		today, _ := time.Parse("2006-01-02", tc.today)
		if !bytes.Contains(Answers(today), []byte(tc.want)) {
			t.Fatal(string(Answers(today)))
		}
	}
}
