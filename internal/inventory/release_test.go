package inventory

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vincentsch/fendkit/internal/detect"
	"github.com/vincentsch/fendkit/internal/profile"
)

func putTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for file, b := range files {
		if e := os.MkdirAll(filepath.Dir(filepath.Join(root, file)), 0755); e != nil {
			t.Fatal(e)
		}
		write(t, root, file, b)
	}
}
func zipTree(t *testing.T, filename string, files map[string]string, prefix string) {
	t.Helper()
	f, e := os.Create(filename)
	if e != nil {
		t.Fatal(e)
	}
	z := zip.NewWriter(f)
	for file, b := range files {
		w, e := z.Create(prefix + file)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write([]byte(b)); e != nil {
			t.Fatal(e)
		}
	}
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
}
func findComponent(t *testing.T, inv Inventory, name, version string) Component {
	t.Helper()
	for _, c := range inv.Components {
		v := ""
		if c.Version != nil {
			v = *c.Version
		}
		if c.Name == name && v == version {
			return c
		}
	}
	t.Fatalf("missing %s %s in %+v", name, version, inv.Components)
	return Component{}
}
func fixture(t *testing.T, root string, opts Options) Inventory {
	t.Helper()
	p, e := detect.Detect(root)
	if e != nil {
		t.Fatal(e)
	}
	inv, e := BuildWithOptions(root, p, opts)
	if e != nil {
		t.Fatal(e)
	}
	return inv
}

func TestReleaseBoundaries(t *testing.T) {
	root := "../../testdata/wp-plugin/acme-booking"
	release := "../dist/acme-booking-2.3.1.zip"
	inv := fixture(t, root, Options{Release: &release})
	if inv.Release == nil || *inv.Release != release || len(inv.Components) != 10 || len(inv.CoverageGaps) != 0 {
		t.Fatalf("wrong inventory: %+v", inv)
	}
	for _, c := range inv.Components {
		want := !c.Development
		if c.Shipped == nil || *c.Shipped != want {
			t.Fatalf("wrong boundary: %+v", c)
		}
	}
	files := map[string]string{
		"plugin.php":                                                      "<?php\n/* Plugin Name: Example\nVersion: 1.0.0\n*/",
		"common/vendor/composer/installed.json":                           `{"packages":[{"name":"vendor/lib","version":"2.0.0","dev":true}]}`,
		"common/vendor/prefixed/composer/installed.json":                  `[{"name":"vendor/other","version":"3.0.0"}]`,
		"common/vendor/composer.lock":                                     "not a lockfile to parse",
		"assets/js/copied.js":                                             "/*! Lodash lodash.com/license */\nx.VERSION=\"4.17.15\";",
		"common/node_modules/@maker/lib/package.json":                     `{"name":"@maker/lib","version":"1.2.3"}`,
		"common/node_modules/@maker/lib/no-banner-scan.js":                "/*! jQuery v1.0.0 */",
		"common/node_modules/@maker/lib/node_modules/nested/package.json": `{"name":"nested","version":"2.0.0"}`,
		"common/node_modules/no-metadata/lib.js":                          "console.log('hello');",
		"common/node_modules/clipboard/lib.js":                            "/*! clipboard.js v2.0.4 */",
	}
	for _, layout := range []string{"flat ZIP", "enclosed ZIP", "folder", "enclosed folder"} {
		t.Run(layout, func(t *testing.T) {
			repo := t.TempDir()
			putTree(t, repo, map[string]string{
				"plugin.php":        files["plugin.php"],
				"package-lock.json": `{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.15","dev":true},"node_modules/runtime":{"version":"1.0.0"}}}`,
				"composer.json":     `{"require":{"vendor/lib":"^2.0"}}`,
				"composer.lock":     `{"packages":[{"name":"vendor/absent","version":"1.0.0"}]}`,
				"assets/absent.js":  "/*! Select2 4.0.5 */",
			})
			releaseDir := t.TempDir()
			selected := filepath.Join(releaseDir, "release.zip")
			switch layout {
			case "flat ZIP":
				zipTree(t, selected, files, "")
			case "enclosed ZIP":
				zipTree(t, selected, files, "example/")
			case "folder":
				selected = releaseDir
				putTree(t, selected, files)
			case "enclosed folder":
				selected = releaseDir
				putTree(t, filepath.Join(selected, "example"), files)
			}
			inv := fixture(t, repo, Options{Release: &selected})
			for _, pair := range [][2]string{{"lodash", "4.17.15"}, {"vendor/lib", "2.0.0"}, {"vendor/other", "3.0.0"}, {"@maker/lib", "1.2.3"}, {"nested", "2.0.0"}, {"no-metadata", ""}, {"clipboard", "2.0.4"}} {
				c := findComponent(t, inv, pair[0], pair[1])
				if c.Shipped == nil || !*c.Shipped || c.Development {
					t.Fatalf("physical release evidence lost: %+v", c)
				}
			}
			lodash := findComponent(t, inv, "lodash", "4.17.15")
			if len(lodash.Evidence) != 2 || lodash.Evidence[0].Path == lodash.Evidence[1].Path {
				t.Fatalf("missing sources: %+v", lodash)
			}
			if findComponent(t, inv, "runtime", "1.0.0").Shipped != nil {
				t.Fatal("runtime npm must stay unknown")
			}
			for _, pair := range [][2]string{{"select2", "4.0.5"}, {"vendor/absent", "1.0.0"}} {
				c := findComponent(t, inv, pair[0], pair[1])
				if c.Shipped == nil || *c.Shipped {
					t.Fatalf("repository-only occurrence shipped: %+v", c)
				}
			}
			for _, c := range inv.Components {
				if c.Name == "jquery" {
					t.Fatal("identified npm package was scanned for banners")
				}
			}
			for _, g := range inv.CoverageGaps {
				if g.Code == "unresolved_runtime_dependency" {
					t.Fatal("release metadata did not resolve dependency")
				}
			}
		})
	}
}

func TestReleaseSelection(t *testing.T) {
	root := t.TempDir()
	putTree(t, root, map[string]string{"plugin.php": "<?php\n/* Plugin Name: Example\nVersion: 1.0.0\n*/"})
	files := map[string]string{"plugin.php": "<?php\n/* Plugin Name: Example\nVersion: 1.0.0\n*/"}
	if e := os.Mkdir(filepath.Join(root, "dist"), 0755); e != nil {
		t.Fatal(e)
	}
	zipTree(t, filepath.Join(root, "dist/example-1.0.0.zip"), files, "")
	inv := fixture(t, root, Options{})
	if inv.Release == nil || *inv.Release != "dist/example-1.0.0.zip" {
		t.Fatal("single ZIP not discovered")
	}
	zipTree(t, filepath.Join(root, "dist/other-1.0.0.zip"), files, "")
	inv = fixture(t, root, Options{})
	if inv.Release != nil || !strings.Contains(strings.Join(inv.Product.Notes, " "), "Several release ZIPs") {
		t.Fatal("ambiguous release selected")
	}
	prof := &profile.Profile{Product: profile.Product{Release: detect.String("dist/example-{version}.zip")}}
	inv = fixture(t, root, Options{Profile: prof})
	if inv.Release == nil || *inv.Release != "dist/example-1.0.0.zip" {
		t.Fatal("pattern not expanded")
	}
	bad := "missing.zip"
	p, _ := detect.Detect(root)
	if _, e := BuildWithOptions(root, p, Options{Profile: prof, Release: &bad}); e == nil || !strings.Contains(e.Error(), "missing or unreadable") {
		t.Fatalf("bad explicit release ignored: %v", e)
	}
	zipTree(t, filepath.Join(root, "wrong.zip"), map[string]string{"plugin.php": "<?php\n/* Plugin Name: Example\nVersion: 2.0.0\n*/"}, "")
	bad = "wrong.zip"
	if _, e := BuildWithOptions(root, p, Options{Release: &bad}); e == nil || !strings.Contains(e.Error(), "2.0.0 differs from project version 1.0.0") {
		t.Fatalf("missing version mismatch: %v", e)
	}
	p.Version = nil
	inv, e := BuildWithOptions(root, p, Options{Profile: prof})
	if e != nil || inv.Release != nil || !strings.Contains(strings.Join(inv.Product.Notes, " "), "needs product.version") {
		t.Fatalf("unknown version expanded: %+v %v", inv, e)
	}
	explicit := "dist/example-1.0.0.zip"
	inv, e = BuildWithOptions(root, p, Options{Release: &explicit})
	if e != nil || inv.Release == nil {
		t.Fatalf("literal release rejected: %v", e)
	}
}

func TestManualOccurrences(t *testing.T) {
	root := t.TempDir()
	putTree(t, root, map[string]string{"first.js": "/*! Select2 4.0.5 */", "second.js": "/*! Select2 4.0.5 */"})
	invBefore := fixture(t, root, Options{Profile: &profile.Profile{Components: []profile.Component{{Path: detect.String("first.js"), Shipped: boolPtr(false)}}}})
	shared := findComponent(t, invBefore, "select2", "4.0.5")
	if shared.Shipped == nil || !*shared.Shipped || len(shared.Evidence) != 3 {
		t.Fatal("another shipped occurrence must win over a manual exclusion")
	}
	prof := &profile.Profile{Components: []profile.Component{{Path: detect.String("first.js"), Version: detect.String("4.0.13"), Shipped: boolPtr(false)}, {Name: detect.String("added"), Ecosystem: detect.String("npm"), Version: detect.String("1.0.0"), Shipped: boolPtr(true)}}}
	inv := fixture(t, root, Options{Profile: prof})
	c := findComponent(t, inv, "select2", "4.0.13")
	if *c.Shipped || len(c.Evidence) != 2 {
		t.Fatal("manual correction lost")
	}
	c = findComponent(t, inv, "select2", "4.0.5")
	if !*c.Shipped || len(c.Evidence) != 1 || c.Source.Path != "second.js" {
		t.Fatal("correction changed another occurrence")
	}
	if !*findComponent(t, inv, "added", "1.0.0").Shipped {
		t.Fatal("manual addition lost")
	}
	prof.Components[0].Path = detect.String("absent.js")
	if _, e := BuildWithOptions(root, detect.Product{}, Options{Profile: prof}); e == nil {
		t.Fatal("unmatched correction silently ignored")
	}
}

func TestPinnedReleaseInventory(t *testing.T) {
	filename := os.Getenv("FENDKIT_TEC_ZIP")
	if filename == "" {
		t.Skip("set FENDKIT_TEC_ZIP to the pinned Events Calendar ZIP")
	}
	f, e := os.Open(filename)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.New()
	_, e = io.Copy(h, f)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != "38c323575fe69c2ee6b2bd596182ca129e1bfcdc7c7118210e05743dfed30159" {
		t.Fatalf("wrong release SHA-256: %s", got)
	}
	root := t.TempDir()
	putTree(t, root, map[string]string{"plugin.php": "<?php\n/* Plugin Name: The Events Calendar\nVersion: 6.18.2\n*/"})
	absolute, e := filepath.Abs(filename)
	if e != nil {
		t.Fatal(e)
	}
	inv := fixture(t, root, Options{Release: &absolute})
	want := map[string]string{"scssphp/scssphp": "v1.13.0", "firebase/php-jwt": "v6.3.2", "monolog/monolog": "2.10.0", "moment": "2.19.3", "select2": "3.5.4-tribe", "woocommerce/selectwoo": "1.0.1", "datatables.net": "1.13.8", "php-date-formatter": "", "intro.js": ""}
	for name, version := range want {
		c := findComponent(t, inv, name, version)
		if c.Shipped == nil || !*c.Shipped {
			t.Fatalf("not shipped: %+v", c)
		}
	}
	findComponent(t, inv, "select2", "4.0.13")
	prefixed := 0
	clipboardFolder := false
	for _, c := range inv.Components {
		for _, ev := range c.Evidence {
			if strings.HasPrefix(ev.Path, "common/vendor/vendor-prefixed/") && c.Ecosystem == "composer" {
				prefixed++
				break
			}
		}
		for _, ev := range c.Evidence {
			if strings.HasPrefix(ev.Path, "common/node_modules/clipboard") {
				clipboardFolder = true
			}
		}
		if c.Name == "." || c.Name == "bootstrap" || c.Name == "jquery-ui" || c.Name == "moment" && *c.Version != "2.19.3" {
			t.Fatalf("false match in real release: %+v", c)
		}
	}
	if prefixed != 29 || !clipboardFolder {
		t.Fatalf("prefixed %d, clipboard folder %v", prefixed, clipboardFolder)
	}
	c := findComponent(t, inv, "select2", "3.5.4-tribe")
	if !c.Modified || *c.LookupVersion != "3.5.4" {
		t.Fatal("modified copy not identified")
	}
	c = findComponent(t, inv, "woocommerce/selectwoo", "1.0.1")
	if c.LookupVersion != nil {
		t.Fatal("fork lookup enabled")
	}
	t.Logf("Pinned SHA-256 verified; %d components, 29 prefixed Composer packages, both Select2 versions and SelectWoo found", len(inv.Components))
}

func TestProductFolderIdentifier(t *testing.T) {
	current, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	p := detect.Product{Type: "wordpress-plugin", Name: detect.String("Different Display Name")}
	want := ProductPURL(current, p)
	if got := ProductPURL(".", p); got != want || got == "pkg:generic/product" {
		t.Fatalf("current directory identity %s, want %s", got, want)
	}
}

func TestComposerDevelopmentLibraryPaths(t *testing.T) {
	root := t.TempDir()
	putTree(t, root, map[string]string{
		"composer.lock":                          `{"packages":[{"name":"maker/runtime","version":"1.0.0"}],"packages-dev":[{"name":"maker/test","version":"1.0.0"}]}`,
		"vendor/composer/installed.json":         `{"packages":[{"name":"maker/test","version":"1.0.0","install-path":"../../tools/test"}]}`,
		"vendor/maker/test/assets/jquery.js":     "/*! jQuery v3.7.1 */",
		"tools/test/assets/bootstrap.js":         "/*! Bootstrap v5.3.6 */",
		"vendor/maker/runtime/assets/select2.js": "/*! Select2 4.0.5 */",
	})
	inv := fixture(t, root, Options{})
	for _, pair := range [][2]string{{"jquery", "3.7.1"}, {"bootstrap", "5.3.6"}} {
		c := findComponent(t, inv, pair[0], pair[1])
		if !c.Development || c.Shipped == nil || *c.Shipped || c.Evidence[0].Shipped == nil || *c.Evidence[0].Shipped {
			t.Fatalf("development library escaped owner classification: %+v", c)
		}
	}
	c := findComponent(t, inv, "select2", "4.0.5")
	if c.Development || c.Shipped == nil || !*c.Shipped {
		t.Fatalf("runtime library lost: %+v", c)
	}
	release := t.TempDir()
	putTree(t, release, map[string]string{"package.json": "{}", "assets/jquery.js": "/*! jQuery v3.7.1 */"})
	inv = fixture(t, root, Options{Release: &release})
	c = findComponent(t, inv, "jquery", "3.7.1")
	if c.Development || c.Shipped == nil || !*c.Shipped || len(c.Evidence) != 2 {
		t.Fatalf("release occurrence must win: %+v", c)
	}
}
