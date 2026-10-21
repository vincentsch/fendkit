package inventory

import (
	"github.com/vincentsch/fendkit/internal/detect"
	"github.com/vincentsch/fendkit/internal/profile"
	"strings"
	"testing"
)

func TestReleaseIdentityConflict(t *testing.T) {
	root := t.TempDir()
	release := t.TempDir()
	putTree(t, root, map[string]string{"plugin.php": "<?php\n/* Plugin Name: Intended\nVersion: 1.0\n*/"})
	putTree(t, release, map[string]string{"plugin.php": "<?php\n/* Plugin Name: Unrelated\nVersion: 1.0\n*/"})
	p, _ := detect.Detect(root)
	_, err := BuildWithOptions(root, p, Options{Release: &release})
	if err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("unrelated release accepted: %v", err)
	}
}
func TestStrippedComposerMetadata(t *testing.T) {
	root := t.TempDir()
	release := t.TempDir()
	putTree(t, root, map[string]string{"composer.lock": `{"packages":[{"name":"guzzlehttp/guzzle","version":"7.4.0"},{"name":"vendor/absent","version":"1.0"}]}`})
	putTree(t, release, map[string]string{"vendor/guzzlehttp/guzzle/src/Client.php": "<?php", "other.txt": "release"})
	inv := fixture(t, root, Options{Release: &release})
	c := findComponent(t, inv, "guzzlehttp/guzzle", "")
	if c.Shipped != nil || c.LookupVersion != nil || strings.Contains(c.PURL, "@") || c.Source.Path != "vendor/guzzlehttp/guzzle" {
		t.Fatalf("fabricated release facts: %+v", c)
	}
	absent := findComponent(t, inv, "vendor/absent", "1.0")
	if absent.Shipped == nil || *absent.Shipped {
		t.Fatal("absent package changed")
	}
}
func TestManualUnknownShipping(t *testing.T) {
	root := t.TempDir()
	release := t.TempDir()
	putTree(t, root, map[string]string{"composer.lock": `{"packages":[{"name":"guzzlehttp/guzzle","version":"7.4.0"}]}`})
	putTree(t, release, map[string]string{"other.txt": "release"})
	p, err := profile.Parse([]byte("version: 1\ncomponents: [{path: vendor/guzzlehttp/guzzle, shipped: null}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	c := findComponent(t, fixture(t, root, Options{Release: &release, Profile: p}), "guzzlehttp/guzzle", "7.4.0")
	if c.Shipped != nil {
		t.Fatal("explicit unknown ignored")
	}
}

func TestIntendedReleaseIdentityLayouts(t *testing.T) {
	for _, kind := range []string{"wordpress-plugin", "wordpress-theme", "composer-package", "npm-package"} {
		for _, layout := range []string{"flat", "wrapped", "directory"} {
			t.Run(kind+"/"+layout, func(t *testing.T) {
				root := t.TempDir()
				out := t.TempDir()
				file, body := "plugin.php", "<?php\n/* Plugin Name: Intended\nVersion: 1.0\n*/"
				switch kind {
				case "wordpress-theme":
					file, body = "style.css", "/* Theme Name: Intended\nVersion: 1.0\n*/"
				case "composer-package":
					file, body = "composer.json", `{"name":"maker/intended","version":"1.0"}`
				case "npm-package":
					file, body = "package.json", `{"name":"intended","version":"1.0"}`
				}
				files := map[string]string{file: body}
				putTree(t, root, files)
				selected := out
				if layout == "directory" {
					putTree(t, out, files)
				} else {
					selected = out + "/release.zip"
					prefix := ""
					if layout == "wrapped" {
						prefix = "arbitrary-wrapper/"
					}
					zipTree(t, selected, files, prefix)
				}
				p := &profile.Profile{Product: profile.Product{Name: detect.String("Maker display name")}}
				inv := fixture(t, root, Options{Release: &selected, Profile: p})
				if *inv.Product.Name != "Maker display name" || strings.Contains(strings.Join(inv.Product.Notes, " "), "identity unverified") {
					t.Fatal(inv.Product)
				}
			})
		}
	}
}
func TestManifestIdentityConflict(t *testing.T) {
	for _, file := range []string{"composer.json", "package.json"} {
		t.Run(file, func(t *testing.T) {
			root := t.TempDir()
			release := t.TempDir()
			putTree(t, root, map[string]string{file: `{"name":"maker/intended","version":"1.0"}`})
			putTree(t, release, map[string]string{file: `{"name":"maker/unrelated","version":"1.0"}`})
			p, _ := detect.Detect(root)
			_, err := BuildWithOptions(root, p, Options{Release: &release})
			if err == nil || !strings.Contains(err.Error(), "identity") {
				t.Fatal(err)
			}
		})
	}
}
func TestUnavailableReleaseIdentity(t *testing.T) {
	root := t.TempDir()
	release := t.TempDir()
	putTree(t, root, map[string]string{"plugin.php": "<?php\n/* Plugin Name: Intended\nVersion: 1.0\n*/"})
	putTree(t, release, map[string]string{"other.txt": "no comparable metadata"})
	inv := fixture(t, root, Options{Release: &release})
	if !strings.Contains(strings.Join(inv.Product.Notes, " "), "Release identity unverified") {
		t.Fatal(inv.Product.Notes)
	}
}
func TestManualOccurrenceGrouping(t *testing.T) {
	for _, tc := range []struct {
		other, correction string
		want              *bool
	}{
		{other: "true", correction: "null", want: boolPtr(true)},
		{other: "false", correction: "null"},
		{other: "false", correction: "false", want: boolPtr(false)},
	} {
		t.Run(tc.other+"/"+tc.correction, func(t *testing.T) {
			a := component("composer", "maker/lib", "1.0", false, Evidence{Path: "vendor/maker/lib"})
			b := component("composer", "maker/lib", "1.0", false, Evidence{Path: "nested/vendor/maker/lib"})
			b.Shipped = boolPtr(tc.other == "true")
			b.Evidence[0].Shipped = b.Shipped
			p, err := profile.Parse([]byte("version: 1\ncomponents: [{path: vendor/maker/lib, shipped: " + tc.correction + "}]"))
			if err != nil {
				t.Fatal(err)
			}
			all, err := applyManual([]Component{a, b}, p.Components)
			if err != nil {
				t.Fatal(err)
			}
			got := mergeComponents(all)[0].Shipped
			if (got == nil) != (tc.want == nil) || got != nil && *got != *tc.want {
				t.Fatal("wrong grouped shipping", got, tc.want)
			}
		})
	}
}

func TestPresentReleaseOccurrenceCorrection(t *testing.T) {
	root := "../../testdata/wp-plugin/acme-booking"
	release := "../dist/acme-booking-2.3.1.zip"
	p, err := profile.Parse([]byte("version: 1\ncomponents: [{path: vendor/guzzlehttp/guzzle, shipped: false}]"))
	if err != nil {
		t.Fatal(err)
	}
	c := findComponent(t, fixture(t, root, Options{Release: &release, Profile: p}), "guzzlehttp/guzzle", "7.4.0")
	if c.Shipped == nil || *c.Shipped {
		t.Fatal("manual physical occurrence correction ignored", c)
	}
}

func TestInstalledComposerVersionRemainsAuthoritative(t *testing.T) {
	root := t.TempDir()
	release := t.TempDir()
	putTree(t, root, map[string]string{"vendor/composer/installed.json": `{"packages":[{"name":"maker/lib","version":"1.0","install-path":"../../common/vendor/maker/lib"}]}`})
	putTree(t, release, map[string]string{
		"common/vendor/composer/installed.json":  `{"packages":[{"name":"maker/lib","version":"2.0"}]}`,
		"common/vendor/maker/lib/src/Client.php": "<?php",
		"other.txt":                              "release",
	})
	inv := fixture(t, root, Options{Release: &release})
	for _, c := range inv.Components {
		if c.Version == nil {
			t.Fatal("known nested version became unknown", c)
		}
	}
	c := findComponent(t, inv, "maker/lib", "2.0")
	if c.Shipped == nil || !*c.Shipped {
		t.Fatal(c)
	}
}
