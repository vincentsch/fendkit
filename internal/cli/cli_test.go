package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vincentsch/fendkit/internal/detect"
	"github.com/vincentsch/fendkit/internal/inventory"
	"github.com/vincentsch/rungrad/testutil"
)

func TestCommandSurface(t *testing.T) { testutil.AssertConsistent(t, New) }

func TestBuiltScan(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "fendkit")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, "../../cmd/fendkit")
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

	t.Run("installed development packages", func(t *testing.T) {
		project := t.TempDir()
		copyTree(t, "../../testdata/wp-plugin/acme-booking", project)
		files := map[string]string{
			"node_modules/webpack/package.json":            `{"name":"webpack","version":"4.46.0"}`,
			"node_modules/lodash/package.json":             `{"name":"lodash","version":"4.17.15"}`,
			"node_modules/lodash/lib.js":                   "/*! jQuery v1.0.0 */",
			"vendor/phpunit/phpunit/coverage/jquery.js":    "/*! jQuery v3.7.1 */",
			"vendor/phpunit/phpunit/coverage/bootstrap.js": "/*! Bootstrap v5.3.6 */",
		}
		for file, data := range files {
			if e := os.MkdirAll(filepath.Dir(filepath.Join(project, file)), 0755); e != nil {
				t.Fatal(e)
			}
			put(t, project, file, data)
		}
		release, e := filepath.Abs("../../testdata/wp-plugin/dist/acme-booking-2.3.1.zip")
		if e != nil {
			t.Fatal(e)
		}
		for _, extra := range [][]string{nil, {"--release", release}} {
			args := append([]string{"scan", "--offline"}, extra...)
			out, _ := run(t, project, 11, args...)
			if !strings.Contains(out, "2 build tools (not shipped)") || !strings.Contains(out, "4 packages to ship, 1 for development only") {
				t.Fatalf("installed packages changed found counts: %s", out)
			}
			if !strings.Contains(out, "not listed anywhere (not shipped):") || !strings.Contains(out, "jQuery 3.7.1") {
				t.Fatal(out)
			}
			data, e := os.ReadFile(filepath.Join(project, "cra/reports/inventory.json"))
			if e != nil {
				t.Fatal(e)
			}
			var report Report
			if e = json.Unmarshal(data, &report); e != nil {
				t.Fatal(e)
			}
			want := map[string]bool{"webpack": false, "lodash": false, "phpunit/phpunit": false, "jquery": false, "bootstrap": false}
			for _, c := range report.Components {
				if _, ok := want[c.Name]; ok {
					if c.Shipped == nil || *c.Shipped || !c.Development {
						t.Fatalf("development package escaped exclusion: %+v", c)
					}
					want[c.Name] = true
				}
			}
			for name, found := range want {
				if !found {
					t.Fatalf("missing %s", name)
				}
			}
			data, e = os.ReadFile(filepath.Join(project, "cra/reports/sbom.cdx.json"))
			if e != nil {
				t.Fatal(e)
			}
			var bom struct {
				Components []struct{ Name, Scope string }
			}
			if e = json.Unmarshal(data, &bom); e != nil {
				t.Fatal(e)
			}
			for _, c := range bom.Components {
				if want[c.Name] && c.Scope != "excluded" {
					t.Fatalf("development package required by SBOM: %+v", c)
				}
			}
		}
	})
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
	for _, want := range []string{"Found", "Acme Booking 2.3.1", "4 packages to ship, 1 for development only", "2 build tools (not shipped)", "Bundled JS         3 libraries in assets/js/vendor/ not listed anywhere:", "moment.js 2.24.0", "Select2 4.0.5", "jQuery Validation 1.19.1", "Release file       none;", "cra/reports/inventory.json"} {
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
	if saved.ScanID == "" || saved.ScannedAt.IsZero() || saved.Complete || !saved.Offline || len(saved.Components) != 10 || len(saved.InventoryDigest) != 64 || saved.Release != nil {
		t.Fatalf("bad provenance: %+v", saved)
	}
	out, errout = run(t, root, 11, "scan", "--offline", "--json")
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
	put(t, root, "cra.yml", "version: 1\nproduct:\n  version: 3.0.0\ncomponents: [{name: manual, version: '5', ecosystem: npm, shipped: true}]\n")
	out, _ = run(t, root, 11, "scan", "--offline", "--json")
	if json.Unmarshal([]byte(out), &result) != nil || *result.ProductVersion != "3.0.0" || *result.Product.DetectedVersion != "2.3.1" || len(result.Components) != 11 {
		t.Fatalf("wrong override: %s", out)
	}
	digestBeforeTriage := result.InventoryDigest
	put(t, root, "cra.yml", "version: 1\nproduct: {version: 3.0.0}\ncomponents: [{name: manual, version: '5', ecosystem: npm, shipped: true}]\nmanufacturer: {name: Example Maker}\ntriage: [{advisory: GHSA-example, component: 'pkg:npm/lodash@4.17.15', status: under_investigation, reason: Reviewing use, decided_on: 2026-10-20}]\n")
	out, _ = run(t, root, 11, "scan", "--offline", "--json")
	if json.Unmarshal([]byte(out), &result) != nil || result.InventoryDigest != digestBeforeTriage {
		t.Fatal("triage or manufacturer changed inventory digest")
	}
	put(t, root, "cra.yml", "version: 1\nproduct: {version: 5.3}\n")
	out, errout = run(t, root, 11, "scan", "--offline", "--json")
	if json.Unmarshal([]byte(out), &result) != nil || result.ProductVersion == nil || *result.ProductVersion != "5.3" || result.Product.DetectedVersion == nil || *result.Product.DetectedVersion != "2.3.1" || errout != "" {
		t.Fatalf("wrong numeric version override: %s %s", out, errout)
	}
	before, _ := os.ReadFile(filepath.Join(root, "cra/reports/inventory.json"))
	put(t, root, "cra.yml", "version: 1\nsupport: {end: tomorrow}\n")
	out, errout = run(t, root, 1, "scan", "--offline", "--json")
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
			out, _ = run(t, project, 11, "scan", "--offline", "--json")
			var r Report
			if json.Unmarshal([]byte(out), &r) != nil || r.ProductVersion != nil || len(r.Components) != 0 || len(r.CoverageGaps) != 1 || strings.Contains(out, "^2.0") {
				t.Fatalf("guessed version or missing gap: %s", out)
			}
			if !strings.Contains(r.CoverageGaps[0].Message, want) {
				t.Fatalf("wrong saved dependency guidance: %+v", r.CoverageGaps[0])
			}
		})
	}

	release, e := filepath.Abs("../../testdata/wp-plugin/dist/acme-booking-2.3.1.zip")
	if e != nil {
		t.Fatal(e)
	}
	out, _ = run(t, root, 11, "scan", "--offline", "--release", release, "--json")
	if e = json.Unmarshal([]byte(out), &result); e != nil || result.Release == nil || *result.Release != expectedReleasePath(t, root, release) {
		t.Fatalf("missing release provenance: %s", out)
	}
	data, e := os.ReadFile(filepath.Join(root, "cra/reports/sbom.cdx.json"))
	if e != nil {
		t.Fatal(e)
	}
	var bom struct {
		Metadata struct {
			Component struct {
				PURL string `json:"purl"`
			}
			Properties []struct{ Name, Value string }
		}
	}
	if e = json.Unmarshal(data, &bom); e != nil || bom.Metadata.Component.PURL != result.Product.PURL {
		t.Fatalf("wrong SBOM: %s", data)
	}
	props := map[string]string{}
	for _, p := range bom.Metadata.Properties {
		props[p.Name] = p.Value
	}
	if props["fendkit:scan_id"] != result.ScanID || props["fendkit:inventory_digest"] != result.InventoryDigest || props["fendkit:complete"] != "false" || props["fendkit:release"] != *result.Release {
		t.Fatal("SBOM provenance differs")
	}
	before, _ = os.ReadFile(filepath.Join(root, "cra/reports/inventory.json"))
	out, errout = run(t, root, 2, "scan", "--release", "missing.zip", "--json")
	if out != "" || !json.Valid([]byte(errout)) || !strings.Contains(errout, "missing or unreadable") {
		t.Fatalf("wrong missing-release error: %s %s", out, errout)
	}
	put(t, root, "cra.yml", "version: 1\nproduct: {version: 9.0.0}\n")
	out, errout = run(t, root, 2, "scan", "--release", release)
	if out != "" || !strings.Contains(errout, "release version 2.3.1 differs from project version 9.0.0") || !strings.Contains(errout, "rebuild the release") {
		t.Fatalf("wrong version error: %s %s", out, errout)
	}
	after, _ = os.ReadFile(filepath.Join(root, "cra/reports/inventory.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("release error replaced inventory")
	}
	put(t, root, "cra.yml", "version: 1\ncomponents: [{path: assets/js/vendor/select2.min.js, version: 4.0.13, shipped: false}]\n")
	out, _ = run(t, root, 11, "scan", "--offline", "--json")
	if !strings.Contains(out, "pkg:npm/select2@4.0.13") || strings.Contains(out, "pkg:npm/select2@4.0.5") {
		t.Fatal("manual correction not applied")
	}
	// A folder boundary gives the same inventory components as its ZIP.
	folder := t.TempDir()
	copyTree(t, "../../testdata/wp-plugin/acme-booking", folder)
	out, _ = run(t, root, 11, "scan", "--offline", "--release", folder, "--json")
	if json.Unmarshal([]byte(out), &result) != nil || result.Release == nil {
		t.Fatal("folder release rejected")
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

func TestBundledSummaryDistinguishesListedLibraries(t *testing.T) {
	var out bytes.Buffer
	renderBundled(&out, []inventory.Component{
		{Name: "moment", Version: detect.String("2.24.0"), Shipped: boolPointer(true), Evidence: []inventory.Evidence{{Path: "assets/vendor/moment.js", Method: "bundled JavaScript"}}},
		{Name: "select2", Version: detect.String("4.0.5"), Shipped: boolPointer(true), Evidence: []inventory.Evidence{{Path: "node_modules/select2", Method: "npm lockfile"}, {Path: "assets/vendor/select2.js", Method: "release bundled JavaScript"}}},
	})
	text := out.String()
	if !strings.Contains(text, "1 library in assets/vendor/ not listed anywhere:\n                     moment.js 2.24.0") || !strings.Contains(text, "1 library in assets/vendor/:\n                     Select2 4.0.5") {
		t.Fatal(text)
	}
}
func boolPointer(v bool) *bool { return &v }

// Overrides are scoped to sequential tests because the conversion is shared.
func forceAbsolutePaths(t *testing.T) {
	t.Helper()
	previous := inventory.RelativePath
	inventory.RelativePath = func(string, string) (string, error) { return "", errors.New("paths are on different volumes") }
	t.Cleanup(func() { inventory.RelativePath = previous })
}

func expectedReleasePath(t *testing.T, base, target string) string {
	t.Helper()
	if filepath.VolumeName(base) != filepath.VolumeName(target) {
		return filepath.ToSlash(filepath.Clean(target))
	}
	relative, err := filepath.Rel(base, target)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.ToSlash(relative)
}
