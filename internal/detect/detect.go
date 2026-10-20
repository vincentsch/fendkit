package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Product struct {
	PURL            string   `json:"purl"`
	PackageName     string   `json:"-"`
	Type            string   `json:"type"`
	Name            *string  `json:"name"`
	Version         *string  `json:"version"`
	DetectedVersion *string  `json:"detected_version"`
	Description     *string  `json:"description"`
	Evidence        []string `json:"evidence"`
	Notes           []string `json:"notes"`
}

func String(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}
func header(b []byte, key string) string {
	re := regexp.MustCompile(`(?mi)^[\s/*#]*` + regexp.QuoteMeta(key) + `:\s*([^\r\n]*)`)
	m := re.FindSubmatch(b)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(string(m[1])), "*/"))
}
func Detect(root string) (Product, error) {
	p := Product{Type: "other", Evidence: []string{}, Notes: []string{}}
	entries, e := os.ReadDir(root)
	if e != nil {
		return p, fmt.Errorf("cannot read project root; check --dir and its permissions")
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".php") {
			continue
		}
		b, e := os.ReadFile(filepath.Join(root, entry.Name()))
		if e != nil {
			return p, fmt.Errorf("%s: cannot read; check file permissions", entry.Name())
		}
		if name := header(b, "Plugin Name"); name != "" {
			if p.Type == "wordpress-plugin" {
				return p, fmt.Errorf("multiple plugin headers in project root; set --dir to one product")
			}
			p.Type = "wordpress-plugin"
			p.Name = String(name)
			p.Version = String(header(b, "Version"))
			p.Description = String(header(b, "Description"))
			p.Evidence = []string{entry.Name()}
		}
	}
	if p.Name == nil {
		b, e := os.ReadFile(filepath.Join(root, "style.css"))
		if e == nil {
			if name := header(b, "Theme Name"); name != "" {
				p.Type = "wordpress-theme"
				p.Name = String(name)
				p.Version = String(header(b, "Version"))
				p.Description = String(header(b, "Description"))
				p.Evidence = []string{"style.css"}
			}
		} else if !os.IsNotExist(e) {
			return p, fmt.Errorf("style.css: cannot read; check permissions")
		}
	}
	if strings.HasPrefix(p.Type, "wordpress-") {
		b, e := os.ReadFile(filepath.Join(root, "readme.txt"))
		if e == nil {
			if stable := header(b, "Stable tag"); stable != "" {
				p.Evidence = append(p.Evidence, "readme.txt")
				if p.Version != nil && stable != "trunk" && stable != *p.Version {
					p.Notes = append(p.Notes, fmt.Sprintf("readme.txt Stable tag %s differs from WordPress header version %s; review and align both versions", stable, *p.Version))
				}
			}
		} else if !os.IsNotExist(e) {
			return p, fmt.Errorf("readme.txt: cannot read; check permissions")
		}
	}
	for _, file := range []string{"composer.json", "package.json"} {
		b, e := os.ReadFile(filepath.Join(root, file))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return p, fmt.Errorf("%s: cannot read; check permissions", file)
		}
		var m struct{ Name, Version, Description string }
		if json.Unmarshal(b, &m) != nil {
			return p, fmt.Errorf("%s: invalid JSON; fix the manifest", file)
		}
		if p.Name == nil {
			p.Type = "composer-package"
			if file == "package.json" {
				p.Type = "npm-package"
			}
			p.PackageName = m.Name
			p.Name = String(m.Name)
			p.Version = String(m.Version)
			p.Description = String(m.Description)
			p.Evidence = []string{file}
		}
	}
	p.DetectedVersion = p.Version
	return p, nil
}
