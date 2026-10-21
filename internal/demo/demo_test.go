package demo

import (
	"archive/zip"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReleasePluginHeaderMatchesSource(t *testing.T) {
	release, err := zip.OpenReader("../../testdata/wp-plugin/dist/acme-booking-2.3.1.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer release.Close()
	header := "acme-booking.php"
	want, err := os.ReadFile(filepath.Join("../../testdata/wp-plugin/acme-booking", header))
	if err != nil {
		t.Fatal(err)
	}
	got, err := fs.ReadFile(release, header)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("release plugin header is stale; update it from the source fixture and run go generate ./internal/demo")
	}
}

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
