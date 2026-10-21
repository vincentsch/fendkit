package sbom

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vincentsch/fendkit/internal/detect"
	"github.com/vincentsch/fendkit/internal/inventory"
	"github.com/vincentsch/fendkit/internal/profile"
)

func validate(t *testing.T, bom *cdx.BOM) {
	t.Helper()
	var b bytes.Buffer
	if e := Write(&b, bom); e != nil {
		t.Fatal(e)
	}
	compiler := jsonschema.NewCompiler()
	for _, file := range []string{"bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"} {
		data, e := os.ReadFile("../../testdata/schema/" + file)
		if e != nil {
			t.Fatal(e)
		}
		var doc any
		if e = json.Unmarshal(data, &doc); e != nil {
			t.Fatal(e)
		}
		if e = compiler.AddResource("http://cyclonedx.org/schema/"+file, doc); e != nil {
			t.Fatal(e)
		}
	}
	schema, e := compiler.Compile("http://cyclonedx.org/schema/bom-1.6.schema.json")
	if e != nil {
		t.Fatal(e)
	}
	var doc any
	if e = json.Unmarshal(b.Bytes(), &doc); e != nil {
		t.Fatal(e)
	}
	if e = schema.Validate(doc); e != nil {
		t.Fatalf("invalid SBOM: %v\n%s", e, b.String())
	}
}
func provenance() Provenance {
	return Provenance{ScanID: "scan-example", ScannedAt: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC), InventoryDigest: strings.Repeat("a", 64), Complete: false, Offline: true, IncompleteReasons: []string{"Offline scan: vulnerability lookups have not run"}}
}
func properties(props *[]cdx.Property) map[string]string {
	out := map[string]string{}
	for _, p := range *props {
		out[p.Name] = p.Value
	}
	return out
}
func TestFixtureSBOM(t *testing.T) {
	root := "../../testdata/wp-plugin/acme-booking"
	p, e := detect.Detect(root)
	if e != nil {
		t.Fatal(e)
	}
	release := "../dist/acme-booking-2.3.1.zip"
	for _, selected := range []*string{nil, &release} {
		inv, e := inventory.BuildWithOptions(root, p, inventory.Options{Release: selected})
		if e != nil {
			t.Fatal(e)
		}
		prof := &profile.Profile{Manufacturer: profile.Manufacturer{Name: detect.String("Example Maker")}}
		bom := New(inv, prof, provenance(), "0.1.0")
		validate(t, bom)
		if bom.Metadata.Component.PackageURL != "pkg:generic/acme-booking@2.3.1" || bom.Metadata.Component.PackageURL != inv.Product.PURL || bom.Metadata.Component.Supplier.Name != "Example Maker" {
			t.Fatalf("wrong product: %+v", bom.Metadata.Component)
		}
		props := properties(bom.Metadata.Properties)
		if props["fendkit:scan_id"] != "scan-example" || props["fendkit:complete"] != "false" || props["fendkit:offline"] != "true" || props["fendkit:inventory_digest"] != provenance().InventoryDigest {
			t.Fatalf("missing provenance: %+v", props)
		}
		for i, c := range *bom.Components {
			source := inv.Components[i]
			want := cdx.ScopeRequired
			if source.Shipped != nil && !*source.Shipped {
				want = cdx.ScopeExcluded
			}
			if c.Scope != want || c.PackageURL != source.PURL || len(*c.Evidence.Occurrences) == 0 {
				t.Fatalf("bad SBOM component: %+v", c)
			}
			if properties(c.Properties)["fendkit:source"] == "" {
				t.Fatal("source lost")
			}
		}
	}
}
func put(t *testing.T, root, file, text string) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(filepath.Join(root, file)), 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, file), []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
}
func TestProductIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		prof  *profile.Profile
		want  string
	}{
		{"theme", map[string]string{"style.css": "/* Theme Name: My Theme\nVersion: 1.2.3\n*/"}, nil, "pkg:generic/my-theme@1.2.3"},
		{"composer", map[string]string{"composer.json": `{"name":"maker/package","version":"1.0.0"}`}, nil, "pkg:composer/maker/package@1.0.0"},
		{"npm", map[string]string{"package.json": `{"name":"@maker/package","version":"1.0.0"}`, "composer.json": `{}`}, nil, "pkg:npm/%40maker/package@1.0.0"},
		{"application", map[string]string{}, &profile.Profile{Product: profile.Product{Type: detect.String("application"), Name: detect.String("My App + Tools"), Version: detect.String("2.0.0+custom")}}, "pkg:generic/my-app-tools@2.0.0+custom"},
		{"other", map[string]string{}, &profile.Profile{Product: profile.Product{Type: detect.String("other"), Name: detect.String("?!")}}, "pkg:generic/product"},
		{"unknown version", map[string]string{"package.json": `{"name":"library"}`}, nil, "pkg:npm/library"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "My Theme")
			if e := os.Mkdir(root, 0755); e != nil {
				t.Fatal(e)
			}
			for file, b := range tc.files {
				put(t, root, file, b)
			}
			p, e := detect.Detect(root)
			if e != nil {
				t.Fatal(e)
			}
			inv, e := inventory.BuildWithOptions(root, p, inventory.Options{Profile: tc.prof})
			if e != nil {
				t.Fatal(e)
			}
			bom := New(inv, tc.prof, provenance(), "0.1.0")
			validate(t, bom)
			if inv.Product.PURL != tc.want || bom.Metadata.Component.PackageURL != tc.want {
				t.Fatalf("want %s, inventory %s, SBOM %s", tc.want, inv.Product.PURL, bom.Metadata.Component.PackageURL)
			}
		})
	}
	for _, eco := range []string{"composer", "npm"} {
		root := "../../testdata/products/" + eco + "-library"
		p, e := detect.Detect(root)
		if e != nil {
			t.Fatal(e)
		}
		inv, e := inventory.Build(root, p)
		if e != nil {
			t.Fatal(e)
		}
		bom := New(inv, nil, provenance(), "0.1.0")
		validate(t, bom)
		if strings.Contains(inv.Product.PURL, "@unknown") || inv.Product.PURL != bom.Metadata.Component.PackageURL || !strings.HasPrefix(inv.Product.PURL, "pkg:"+eco+"/") || len(inv.CoverageGaps) != 1 {
			t.Fatalf("wrong unknown product: %+v", inv)
		}
	}
}
func TestReleaseScopeAndEvidence(t *testing.T) {
	root := t.TempDir()
	put(t, root, "package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.15","dev":true},"node_modules/runtime":{"version":"2.0.0"}}}`)
	put(t, root, "assets/absent.js", "/*! Select2 4.0.5 */")
	release := t.TempDir()
	put(t, release, "package.json", `{"name":"release"}`)
	put(t, release, "assets/copied.js", "/*! Lodash lodash.com/license */x.VERSION=\"4.17.15\";")
	put(t, release, "assets/modified.js", "/*! Select2 3.5.4-tribe */")
	put(t, release, "assets/unknown.js", "/*! Popper.js */")
	inv, e := inventory.BuildWithOptions(root, detect.Product{}, inventory.Options{Release: &release})
	if e != nil {
		t.Fatal(e)
	}
	bom := New(inv, nil, provenance(), "0.1.0")
	validate(t, bom)
	for _, c := range *bom.Components {
		switch c.PackageURL {
		case "pkg:npm/runtime@2.0.0":
			if c.Scope != cdx.ScopeRequired || properties(c.Properties)["fendkit:shipped"] != "unknown" {
				t.Fatal("unknown shipment must have required scope")
			}
		case "pkg:npm/lodash@4.17.15":
			if c.Scope != cdx.ScopeRequired || len(*c.Evidence.Occurrences) != 2 {
				t.Fatalf("release occurrence lost: %+v", c)
			}
		case "pkg:npm/select2@4.0.5":
			if c.Scope != cdx.ScopeExcluded {
				t.Fatal("absent library required")
			}
		case "pkg:npm/select2@3.5.4-tribe":
			if c.Modified == nil || !*c.Modified || properties(c.Properties)["fendkit:note"] == "" {
				t.Fatal("modified evidence lost")
			}
		case "pkg:npm/popper.js":
			if c.Version != "" || c.Scope != cdx.ScopeRequired || properties(c.Properties)["fendkit:banner"] == "" {
				t.Fatal("unknown version evidence lost")
			}
		default:
			t.Fatalf("unexpected component: %+v", c)
		}
	}
}
