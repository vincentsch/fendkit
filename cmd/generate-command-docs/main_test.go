package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vincentsch/fendkit/internal/version"
)

func TestReferenceDriftAndPruning(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("docs/media", 0755); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"docs/guide.md", "docs/media/image.svg"} {
		if err := os.WriteFile(file, []byte("handwritten"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := generate(false); err != nil {
		t.Fatal(err)
	}
	if err := generate(true); err != nil {
		t.Fatal(err)
	}
	first := reference()
	for _, want := range []string{"Apply product settings and manual components from cra.yml.", "--release string", "--dir string", `Project root (default ".")`, "OSV.dev", "Exit 0"} {
		if !strings.Contains(first["fendkit_scan.md"], want) {
			t.Fatalf("missing help detail %q", want)
		}
	}
	if !strings.Contains(first["fendkit_triage.md"], "fendkit triage <advisory-id>") {
		t.Fatal("missing positional argument syntax")
	}
	if err := generate(false); err != nil {
		t.Fatal(err)
	}
	for path, want := range first {
		got, err := os.ReadFile(filepath.Join("docs/reference", path))
		if err != nil || string(got) != want {
			t.Fatalf("nondeterministic page %s: %v", path, err)
		}
	}
	page := filepath.Join("docs", "reference", "fendkit_scan.md")
	if err := os.WriteFile(page, []byte("drift"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := generate(true); err == nil {
		t.Fatal("check accepted stale content")
	}
	if b, err := os.ReadFile(page); err != nil || string(b) != "drift" {
		t.Fatal("check modified content")
	}
	orphan := "docs/reference/obsolete.md"
	if err := os.WriteFile(orphan, []byte("obsolete"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := generate(false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatal("orphan was not pruned")
	}
	// The command tree must generate identical content for another build identity.
	originalVersion, originalCommit := version.Version, version.Commit
	t.Cleanup(func() { version.Version, version.Commit = originalVersion, originalCommit })
	version.Version, version.Commit = "9.8.7", "another-commit"
	if err := generate(true); err != nil {
		t.Fatal("reference depends on build metadata:", err)
	}
	for _, file := range []string{"docs/guide.md", "docs/media/image.svg"} {
		if b, err := os.ReadFile(file); err != nil || string(b) != "handwritten" {
			t.Fatalf("handwritten file changed: %s", file)
		}
	}
}
