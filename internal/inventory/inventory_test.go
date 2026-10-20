package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vincentsch/conformline/internal/detect"
)

func TestFixtureInventory(t *testing.T) {
	root := "../../testdata/wp-plugin/acme-booking"
	p, e := detect.Detect(root)
	if e != nil {
		t.Fatal(e)
	}
	inv, e := Build(root, p)
	if e != nil {
		t.Fatal(e)
	}
	if len(inv.Components) != 7 || len(inv.CoverageGaps) != 0 {
		t.Fatalf("components %d gaps %+v", len(inv.Components), inv.CoverageGaps)
	}
	runtime := map[string]bool{"guzzlehttp/guzzle": true, "guzzlehttp/psr7": true, "guzzlehttp/promises": true, "psr/http-message": true}
	for _, c := range inv.Components {
		want := runtime[c.Name]
		if c.Shipped == nil || *c.Shipped != want || c.Development == want {
			t.Fatalf("wrong boundary: %+v", c)
		}
		if want && len(c.Evidence) != 2 {
			t.Fatalf("missing occurrences: %+v", c)
		}
	}
	a, e := inv.Digest()
	if e != nil {
		t.Fatal(e)
	}
	again, e := Build(root, p)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := again.Digest()
	if a != b {
		t.Fatal("unstable digest")
	}
	again.Components[0].Version = detect.String("99.0.0")
	b, _ = again.Digest()
	if a == b {
		t.Fatal("digest ignored change")
	}
}
func TestComposerFormats(t *testing.T) {
	for _, input := range []string{`[{"name":"vendor/lib","version":"v2.0.0"},{"name":"vendor/test","version":"1.0.0","dev":true}]`, `{"packages":[{"name":"vendor/lib","version":"v2.0.0"},{"name":"vendor/test","version":"1.0.0"}],"dev-package-names":["vendor/test"]}`} {
		cs, e := Installed([]byte(input), "vendor/composer/installed.json")
		if e != nil {
			t.Fatal(e)
		}
		if len(cs) != 2 || cs[0].PURL != "pkg:composer/vendor/lib@2.0.0" || *cs[0].Version != "v2.0.0" || *cs[0].LookupVersion != "2.0.0" || !*cs[0].Shipped || *cs[1].Shipped {
			t.Fatalf("wrong installed data: %+v", cs)
		}
	}
	cs, e := ComposerLock([]byte(`{"packages":[{"name":"vendor/lib","version":"v2.0.0"}],"packages-dev":[{"name":"vendor/test","version":"1.0.0"}]}`), "composer.lock")
	if e != nil || len(cs) != 2 || !*cs[0].Shipped || *cs[1].Shipped {
		t.Fatalf("wrong composer lock: %+v %v", cs, e)
	}
}
func TestNPMFormats(t *testing.T) {
	for _, file := range []string{"package-lock-v2.json", "npm-shrinkwrap.json"} {
		b, e := os.ReadFile("../../testdata/lockfiles/" + file)
		if e != nil {
			t.Fatal(e)
		}
		cs, e := NPMLock(b, file)
		if e != nil {
			t.Fatal(e)
		}
		if len(cs) != 1 || cs[0].Name != "lodash" || cs[0].Shipped != nil || *cs[0].Version != "4.17.21" {
			t.Fatalf("bad npm parse: %+v", cs)
		}
	}
	cs, e := NPMLock([]byte(`{"lockfileVersion":3,"packages":{"":{"name":"product"},"node_modules/@maker/tool":{"version":"v1.0.0"},"node_modules/build":{"version":"2.0.0","dev":true},"node_modules/build/node_modules/nested":{"version":"3.0.0","dev":true}}}`), "package-lock.json")
	if e != nil {
		t.Fatal(e)
	}
	if len(cs) != 3 || cs[0].PURL != "pkg:npm/%40maker/tool@1.0.0" || cs[0].Shipped != nil {
		t.Fatalf("bad scoped npm package: %+v", cs)
	}
}
func TestCoverageGaps(t *testing.T) {
	for _, eco := range []string{"composer", "npm"} {
		t.Run(eco, func(t *testing.T) {
			root := t.TempDir()
			manifest := `{"name":"maker/library","require":{"php":">=8.1","vendor/missing":"^2.0"}}`
			file := "composer.json"
			if eco == "npm" {
				manifest = `{"name":"library","dependencies":{"missing":"^2.0"}}`
				file = "package.json"
			}
			write(t, root, file, manifest)
			write(t, root, "yarn.lock", "unsupported")
			write(t, root, "pnpm-lock.yaml", "unsupported")
			p, e := detect.Detect(root)
			if e != nil {
				t.Fatal(e)
			}
			inv, e := Build(root, p)
			if e != nil {
				t.Fatal(e)
			}
			if p.Version != nil || len(inv.Components) != 0 || len(inv.CoverageGaps) != 3 {
				t.Fatalf("unexpected evidence: %+v", inv)
			}
			b, _ := json.Marshal(inv)
			if strings.Contains(string(b), "^2.0") {
				t.Fatal("constraint used as installed version")
			}
		})
	}
}
func TestShrinkwrapPrecedence(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/tool":{"version":"1.0.0"}}}`)
	write(t, root, "npm-shrinkwrap.json", `{"lockfileVersion":2,"packages":{"node_modules/tool":{"version":"2.0.0"}}}`)
	inv, e := Build(root, detect.Product{})
	if e != nil || len(inv.Components) != 1 || *inv.Components[0].Version != "2.0.0" {
		t.Fatalf("shrinkwrap ignored: %+v %v", inv, e)
	}
}
func TestMalformedMetadata(t *testing.T) {
	for _, tc := range []struct {
		parse func([]byte, string) ([]Component, error)
		text  string
	}{{ComposerLock, `{"packages":[{"name":"vendor/lib"}]}`}, {Installed, `{"packages":"bad"}`}, {NPMLock, `{"lockfileVersion":1,"dependencies":{}}`}, {NPMLock, `broken`}} {
		if _, e := tc.parse([]byte(tc.text), "lockfile"); e == nil || !strings.Contains(e.Error(), "regenerate") {
			t.Fatalf("need repair action: %v", e)
		}
	}
}
func write(t *testing.T, root, file, b string) {
	t.Helper()
	if e := os.WriteFile(filepath.Join(root, file), []byte(b), 0600); e != nil {
		t.Fatal(e)
	}
}

func TestRuntimeOccurrenceWins(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/build/node_modules/shared":{"version":"1.0.0","dev":true},"node_modules/shared":{"version":"1.0.0"}}}`)
	inv, e := Build(root, detect.Product{})
	if e != nil {
		t.Fatal(e)
	}
	if len(inv.Components) != 1 || inv.Components[0].Development || inv.Components[0].Shipped != nil || len(inv.Components[0].Evidence) != 2 {
		t.Fatalf("runtime occurrence lost: %+v", inv.Components)
	}
}
func TestInstalledPath(t *testing.T) {
	cs, e := Installed([]byte(`{"packages":[{"name":"maker/plugin","version":"1.0.0","install-path":"../../plugins/plugin"}]}`), "vendor/composer/installed.json")
	if e != nil || len(cs) != 1 || cs[0].Evidence[0].Path != "plugins/plugin" {
		t.Fatalf("wrong occurrence path: %+v %v", cs, e)
	}
}
