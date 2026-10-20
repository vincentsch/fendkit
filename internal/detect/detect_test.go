package detect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductDetection(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		files                   map[string]string
		kind, nameWant, version string
	}{
		{"plugin takes precedence", map[string]string{"plugin.php": "<?php\n/**\n * Plugin Name: Booking\n * Version: 2.3.1\n * Description: Make bookings.\n */", "composer.json": `{"name":"vendor/package"}`, "package.json": `{"name":"build-tools","version":"9.0.0"}`, "readme.txt": "Stable tag: 2.3.0"}, "wordpress-plugin", "Booking", "2.3.1"},
		{"theme", map[string]string{"style.css": "/*\nTheme Name: Garden\nVersion: 1.2.0\nDescription: A garden theme.\n*/"}, "wordpress-theme", "Garden", "1.2.0"},
		{"composer", map[string]string{"composer.json": `{"name":"maker/library","version":"v1.0.0","description":"A library"}`}, "composer-package", "maker/library", "v1.0.0"},
		{"composer without version", map[string]string{"composer.json": `{"name":"maker/library","require":{"vendor/missing":"^2.0"}}`}, "composer-package", "maker/library", ""},
		{"npm", map[string]string{"package.json": `{"name":"@maker/library","version":"1.0.0"}`}, "npm-package", "@maker/library", "1.0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for name, b := range tc.files {
				if e := os.WriteFile(filepath.Join(root, name), []byte(b), 0600); e != nil {
					t.Fatal(e)
				}
			}
			p, e := Detect(root)
			if e != nil {
				t.Fatal(e)
			}
			if p.Type != tc.kind || p.Name == nil || *p.Name != tc.nameWant {
				t.Fatalf("unexpected product: %+v", p)
			}
			if tc.version == "" {
				if p.Version != nil {
					t.Fatal("invented version")
				}
			} else if p.Version == nil || *p.Version != tc.version {
				t.Fatal("wrong version")
			}
			if tc.name == "plugin takes precedence" && (len(p.Notes) != 1 || !strings.Contains(p.Notes[0], "Stable tag")) {
				t.Fatal("missing stable tag mismatch")
			}
		})
	}
}
