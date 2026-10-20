package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vincentsch/conformline/internal/docs"
	"github.com/vincentsch/conformline/internal/version"
	"github.com/vincentsch/rungrad/testutil"
)

func TestSharedVersionMetadata(t *testing.T) {
	result := testutil.RunWith(New(), testutil.Options{}, "--version")
	if result.Exit != 0 || !strings.Contains(result.Stdout, "conformline "+version.Version+" (commit "+version.Commit+", "+runtime.Version()+")") {
		t.Fatalf("%+v", result)
	}
	result = testutil.RunWith(New(), testutil.Options{}, "__rungrad_manifest")
	var manifest struct {
		ToolVersion string `json:"tool_version"`
	}
	if result.Exit != 0 || json.Unmarshal([]byte(result.Stdout), &manifest) != nil || manifest.ToolVersion != version.Version {
		t.Fatalf("manifest: %+v", result)
	}
	out := filepath.Join(t.TempDir(), "demo")
	result = testutil.RunWith(New(), testutil.Options{}, "demo", "--offline", "--out", out)
	if result.Exit != 11 {
		t.Fatalf("%+v", result)
	}
	root := filepath.Join(out, "acme-booking")
	for _, file := range append(append([]string{}, docs.Files...), "cra/README.md", "cra/reports/status.md", "cra/reports/status.html") {
		b, err := os.ReadFile(filepath.Join(root, file))
		want := "conformline: " + version.Version
		if strings.HasSuffix(file, "security.txt") {
			want = "# " + want
		}
		if strings.Contains(file, "/status.") {
			want = "Conformline " + version.Version
		}
		if err != nil || !strings.Contains(string(b), want) {
			t.Errorf("%s: missing %q (%v)", file, want, err)
		}
	}
	b, err := os.ReadFile(filepath.Join(root, "cra/reports/sbom.cdx.json"))
	var bom struct {
		Metadata struct {
			Tools struct {
				Components []struct{ Name, Version string }
			}
		}
	}
	if err != nil || json.Unmarshal(b, &bom) != nil {
		t.Fatal("cannot read SBOM", err)
	}
	if len(bom.Metadata.Tools.Components) != 1 || bom.Metadata.Tools.Components[0].Name != "conformline" || bom.Metadata.Tools.Components[0].Version != version.Version {
		t.Fatalf("tool metadata: %+v", bom)
	}
	summary := filepath.Join(t.TempDir(), "summary.md")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	result = testutil.RunWith(New(), testutil.Options{}, "check", "--ci", "--dir", root)
	b, err = os.ReadFile(summary)
	if result.Exit != 11 || err != nil || !strings.Contains(string(b), "Conformline "+version.Version) {
		t.Fatalf("summary: %+v %v", result, err)
	}
}
