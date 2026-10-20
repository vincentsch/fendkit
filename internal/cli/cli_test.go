package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vincentsch/rungrad/testutil"
)

func TestCommandSurface(t *testing.T) { testutil.AssertConsistent(t, New) }

func TestBuiltScan(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "conformline")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/conformline")
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build: %s %v", b, e)
	}
	run := func(t *testing.T, root string, code int, args ...string) (string, string) {
		t.Helper()
		args = append(args, "--dir", root, "--no-prompt")
		cmd := exec.Command(binary, args...)
		var out, err bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &err
		e := cmd.Run()
		got := 0
		if e != nil {
			if exit, ok := e.(*exec.ExitError); ok {
				got = exit.ExitCode()
			} else {
				t.Fatal(e)
			}
		}
		if got != code {
			t.Fatalf("%v: exit %d, want %d\n%s\n%s", args, got, code, out.String(), err.String())
		}
		return out.String(), err.String()
	}
	root := t.TempDir()
	copyTree(t, "../../testdata/wp-plugin/acme-booking", root)
	out, errout := run(t, root, 11, "scan", "--offline", "--dry-run")
	if errout != "" || !strings.Contains(out, "DRY RUN") {
		t.Fatalf("bad preview: %s %s", out, errout)
	}
	if _, e := os.Stat(filepath.Join(root, "cra")); !os.IsNotExist(e) {
		t.Fatal("dry-run created cra")
	}
	out, errout = run(t, root, 11, "scan", "--offline")
	for _, want := range []string{"Found", "Acme Booking 2.3.1", "4 packages to ship, 1 for development only", "2 build tools (not shipped)", "Bundled JS         not checked yet", "Release file       not checked yet", "cra/reports/inventory.json"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
	if errout != "" {
		t.Fatal(errout)
	}
	b, e := os.ReadFile(filepath.Join(root, "cra/reports/inventory.json"))
	if e != nil {
		t.Fatal(e)
	}
	var saved Report
	if e = json.Unmarshal(b, &saved); e != nil {
		t.Fatal(e)
	}
	if saved.ScanID == "" || saved.ScannedAt.IsZero() || saved.Complete || !saved.Offline || len(saved.Components) != 7 || len(saved.InventoryDigest) != 64 || saved.Release != nil {
		t.Fatalf("bad provenance: %+v", saved)
	}
	out, errout = run(t, root, 11, "scan", "--json")
	var result Report
	decoder := json.NewDecoder(strings.NewReader(out))
	if e = decoder.Decode(&result); e != nil {
		t.Fatal(e)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || errout != "" {
		t.Fatalf("expected one JSON result: %s %s", out, errout)
	}
	if result.InventoryDigest != saved.InventoryDigest || result.ScanID == saved.ScanID {
		t.Fatal("digest or scan identity wrong")
	}
	if _, e = os.Stat(filepath.Join(root, "cra.yml")); !os.IsNotExist(e) {
		t.Fatal("scan created profile")
	}
	put(t, root, "cra.yml", "version: 1\nproduct:\n  version: 3.0.0\n  release: absent.zip\ncomponents: [{name: manual, version: '5', ecosystem: npm, shipped: true}]\n")
	out, _ = run(t, root, 11, "scan", "--json")
	if json.Unmarshal([]byte(out), &result) != nil || *result.ProductVersion != "3.0.0" || *result.Product.DetectedVersion != "2.3.1" || len(result.Components) != 7 {
		t.Fatalf("wrong override: %s", out)
	}
	digestBeforeTriage := result.InventoryDigest
	put(t, root, "cra.yml", "version: 1\nproduct: {version: 3.0.0}\nmanufacturer: {name: Example Maker}\ntriage: [{advisory: GHSA-example, component: 'pkg:npm/lodash@4.17.15', status: under_investigation, reason: Reviewing use, decided_on: 2026-10-20}]\n")
	out, _ = run(t, root, 11, "scan", "--json")
	if json.Unmarshal([]byte(out), &result) != nil || result.InventoryDigest != digestBeforeTriage {
		t.Fatal("triage or manufacturer changed inventory digest")
	}
	put(t, root, "cra.yml", "version: 1\nproduct: {version: 5.3}\n")
	out, errout = run(t, root, 11, "scan", "--json")
	if json.Unmarshal([]byte(out), &result) != nil || result.ProductVersion == nil || *result.ProductVersion != "5.3" || result.Product.DetectedVersion == nil || *result.Product.DetectedVersion != "2.3.1" || errout != "" {
		t.Fatalf("wrong numeric version override: %s %s", out, errout)
	}
	before, _ := os.ReadFile(filepath.Join(root, "cra/reports/inventory.json"))
	put(t, root, "cra.yml", "version: 1\nsupport: {end: tomorrow}\n")
	out, errout = run(t, root, 1, "scan", "--json")
	if out != "" || !json.Valid([]byte(errout)) || !strings.Contains(errout, "support.end") || !strings.Contains(errout, "YYYY-MM-DD") {
		t.Fatalf("bad profile error: %s %s", out, errout)
	}
	after, _ := os.ReadFile(filepath.Join(root, "cra/reports/inventory.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("invalid profile replaced report")
	}
	if e = os.Remove(filepath.Join(root, "cra.yml")); e != nil {
		t.Fatal(e)
	}
	put(t, root, "yarn.lock", "# sample\n")
	out, _ = run(t, root, 11, "scan", "--offline")
	if !strings.Contains(out, "yarn.lock is not supported yet") || !strings.Contains(out, "Coverage gap") {
		t.Fatal(out)
	}
	for _, eco := range []string{"composer", "npm"} {
		t.Run("unresolved "+eco, func(t *testing.T) {
			project := t.TempDir()
			copyTree(t, "../../testdata/products/"+eco+"-library", project)
			out, _ := run(t, project, 11, "scan", "--offline")
			if !strings.Contains(out, "Set product.version") || !strings.Contains(out, "no resolved runtime version") {
				t.Fatal(out)
			}
			want := "supply composer.lock or vendor/composer/installed.json"
			if eco == "npm" {
				want = "supply package-lock.json (v2/v3) or npm-shrinkwrap.json"
			}
			if !strings.Contains(out, want) || (eco == "npm" && strings.Contains(out, "or Composer installed metadata")) {
				t.Fatalf("wrong dependency repair guidance: %s", out)
			}
			out, _ = run(t, project, 11, "scan", "--json")
			var r Report
			if json.Unmarshal([]byte(out), &r) != nil || r.ProductVersion != nil || len(r.Components) != 0 || len(r.CoverageGaps) != 1 || strings.Contains(out, "^2.0") {
				t.Fatalf("guessed version or missing gap: %s", out)
			}
			if !strings.Contains(r.CoverageGaps[0].Message, want) {
				t.Fatalf("wrong saved dependency guidance: %+v", r.CoverageGaps[0])
			}
		})
	}
	out, errout = run(t, root, 1, "scan", "--unknown")
	if !strings.Contains(errout, "unknown flag") {
		t.Fatalf("bad usage: %s %s", out, errout)
	}
}
func put(t *testing.T, root, file, text string) {
	t.Helper()
	if e := os.WriteFile(filepath.Join(root, file), []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
}
func copyTree(t *testing.T, source, target string) {
	t.Helper()
	if e := filepath.WalkDir(source, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		relative, e := filepath.Rel(source, p)
		if e != nil {
			return e
		}
		dest := filepath.Join(target, relative)
		if d.IsDir() {
			return os.MkdirAll(dest, 0755)
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		return os.WriteFile(dest, b, 0644)
	}); e != nil {
		t.Fatal(e)
	}
}
