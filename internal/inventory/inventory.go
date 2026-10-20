package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vincentsch/conformline/internal/detect"
)

type Evidence struct {
	File   string `json:"file"`
	Method string `json:"method"`
	Path   string `json:"path"`
}
type Component struct {
	Name          string     `json:"name"`
	Version       *string    `json:"version"`
	LookupVersion *string    `json:"lookup_version"`
	Ecosystem     string     `json:"ecosystem"`
	PURL          string     `json:"purl"`
	Shipped       *bool      `json:"shipped"`
	Development   bool       `json:"development"`
	Source        Evidence   `json:"source"`
	Evidence      []Evidence `json:"evidence"`
}
type Gap struct {
	Code    string `json:"code"`
	File    string `json:"file"`
	Package string `json:"package,omitempty"`
	Message string `json:"message"`
}
type Inventory struct {
	Product      detect.Product `json:"product"`
	Release      *string        `json:"release"`
	Components   []Component    `json:"components"`
	CoverageGaps []Gap          `json:"coverage_gaps"`
}

func boolPtr(v bool) *bool { return &v }
func PURL(ecosystem, name, version string) string {
	parts := strings.Split(name, "/")
	for i, s := range parts {
		parts[i] = strings.ReplaceAll(url.PathEscape(s), "@", "%40")
	}
	p := "pkg:" + ecosystem + "/" + strings.Join(parts, "/")
	if version != "" {
		p += "@" + url.PathEscape(strings.TrimPrefix(version, "v"))
	}
	return p
}
func component(eco, name, version string, dev bool, ev Evidence) Component {
	var shipped *bool
	if eco == "composer" || dev {
		shipped = boolPtr(!dev)
	}
	return Component{Name: name, Version: detect.String(version), LookupVersion: detect.String(strings.TrimPrefix(version, "v")), Ecosystem: eco, PURL: PURL(eco, name, version), Shipped: shipped, Development: dev, Source: ev, Evidence: []Evidence{ev}}
}

type composerPackage struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Dev         *bool  `json:"dev"`
	InstallPath string `json:"install-path"`
}

func ComposerLock(b []byte, file string) ([]Component, error) {
	var m struct {
		Packages []composerPackage `json:"packages"`
		Dev      []composerPackage `json:"packages-dev"`
	}
	if e := json.Unmarshal(b, &m); e != nil {
		return nil, fmt.Errorf("%s: invalid Composer lockfile; regenerate it with Composer", file)
	}
	if m.Packages == nil {
		return nil, fmt.Errorf("%s: missing packages; regenerate it with Composer", file)
	}
	out := []Component{}
	for _, group := range []struct {
		list []composerPackage
		dev  bool
	}{{m.Packages, false}, {m.Dev, true}} {
		for _, p := range group.list {
			if p.Name == "" || p.Version == "" {
				return nil, fmt.Errorf("%s: package name or version missing; regenerate it with Composer", file)
			}
			out = append(out, component("composer", p.Name, p.Version, group.dev, Evidence{file, "composer.lock", "vendor/" + p.Name}))
		}
	}
	return out, nil
}
func Installed(b []byte, file string) ([]Component, error) {
	var packages []composerPackage
	var names []string
	if strings.HasPrefix(strings.TrimSpace(string(b)), "[") {
		if json.Unmarshal(b, &packages) != nil {
			return nil, fmt.Errorf("%s: invalid installed metadata; regenerate it with Composer", file)
		}
	} else {
		var m struct {
			Packages []composerPackage `json:"packages"`
			Names    []string          `json:"dev-package-names"`
		}
		if json.Unmarshal(b, &m) != nil || m.Packages == nil {
			return nil, fmt.Errorf("%s: invalid installed metadata; regenerate it with Composer", file)
		}
		packages = m.Packages
		names = m.Names
	}
	out := []Component{}
	for _, p := range packages {
		if p.Name == "" || p.Version == "" {
			return nil, fmt.Errorf("%s: package name or version missing; regenerate it with Composer", file)
		}
		dev := false
		if p.Dev != nil {
			dev = *p.Dev
		}
		for _, name := range names {
			if name == p.Name {
				dev = true
			}
		}
		occurrence := path.Join(path.Dir(path.Dir(file)), p.Name)
		if p.InstallPath != "" {
			occurrence = path.Join(path.Dir(file), p.InstallPath)
		}
		out = append(out, component("composer", p.Name, p.Version, dev, Evidence{file, "installed.json", occurrence}))
	}
	return out, nil
}
func NPMLock(b []byte, file string) ([]Component, error) {
	var m struct {
		Version  int `json:"lockfileVersion"`
		Packages map[string]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
			Link    bool   `json:"link"`
		} `json:"packages"`
	}
	if json.Unmarshal(b, &m) != nil {
		return nil, fmt.Errorf("%s: invalid JSON; regenerate it with npm", file)
	}
	if (m.Version != 2 && m.Version != 3) || m.Packages == nil {
		return nil, fmt.Errorf("%s: only npm lockfile versions 2 and 3 are supported; regenerate it with a current npm", file)
	}
	out := []Component{}
	keys := []string{}
	for k := range m.Packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := m.Packages[k]
		if k == "" || p.Link {
			continue
		}
		idx := strings.LastIndex(k, "node_modules/")
		if idx < 0 {
			continue
		}
		name := k[idx+len("node_modules/"):]
		if p.Name != "" {
			name = p.Name
		}
		if name == "" {
			return nil, fmt.Errorf("%s: package name missing; regenerate it with npm", file)
		}
		out = append(out, component("npm", name, p.Version, p.Dev, Evidence{file, "npm lockfile", k}))
	}
	return out, nil
}
func read(root, file string) ([]byte, error) {
	b, e := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
	if e != nil && !os.IsNotExist(e) {
		return nil, fmt.Errorf("%s: cannot read; check permissions", file)
	}
	return b, e
}
func Build(root string, product detect.Product) (Inventory, error) {
	inv := Inventory{Product: product, Components: []Component{}, CoverageGaps: []Gap{}}
	add := func(cs []Component) {
		for _, c := range cs {
			merged := false
			for i := range inv.Components {
				old := &inv.Components[i]
				if old.PURL == c.PURL {
					old.Evidence = append(old.Evidence, c.Evidence...)
					// A runtime npm occurrence keeps a package possibly shipped even if another occurrence is development only.
					if c.Ecosystem == "npm" {
						old.Development = old.Development && c.Development
						if old.Shipped == nil || c.Shipped == nil {
							old.Shipped = nil
						}
					}
					merged = true
					break
				}
			}
			if !merged {
				inv.Components = append(inv.Components, c)
			}
		}
	}
	for _, spec := range []struct {
		file  string
		parse func([]byte, string) ([]Component, error)
	}{{"composer.lock", ComposerLock}, {"vendor/composer/installed.json", Installed}} {
		b, e := read(root, spec.file)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return inv, e
		}
		cs, e := spec.parse(b, spec.file)
		if e != nil {
			return inv, e
		}
		add(cs)
	}
	// npm gives shrinkwrap precedence when both lockfiles exist.
	for _, file := range []string{"npm-shrinkwrap.json", "package-lock.json"} {
		b, e := read(root, file)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return inv, e
		}
		cs, e := NPMLock(b, file)
		if e != nil {
			return inv, e
		}
		add(cs)
		break
	}
	for _, file := range []string{"pnpm-lock.yaml", "yarn.lock"} {
		_, e := read(root, file)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return inv, e
		}
		inv.CoverageGaps = append(inv.CoverageGaps, Gap{Code: "unsupported_lockfile", File: file, Message: file + " is not supported yet; supply npm package-lock.json v2/v3 or npm-shrinkwrap.json for dependency coverage"})
	}
	for _, eco := range []string{"composer", "npm"} {
		file := "composer.json"
		if eco == "npm" {
			file = "package.json"
		}
		b, e := read(root, file)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return inv, e
		}
		var m struct {
			Require      map[string]string `json:"require"`
			Dependencies map[string]string `json:"dependencies"`
		}
		if json.Unmarshal(b, &m) != nil {
			return inv, fmt.Errorf("%s: invalid dependency declarations; fix the manifest JSON", file)
		}
		deps := m.Require
		if eco == "npm" {
			deps = m.Dependencies
		}
		names := []string{}
		for name := range deps {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if eco == "composer" && !strings.Contains(name, "/") {
				continue
			}
			found := false
			for _, c := range inv.Components {
				if c.Ecosystem == eco && c.Name == name && !c.Development {
					found = true
					break
				}
			}
			if !found {
				next := "supply composer.lock or vendor/composer/installed.json"
				if eco == "npm" {
					next = "supply package-lock.json (v2/v3) or npm-shrinkwrap.json"
				}
				inv.CoverageGaps = append(inv.CoverageGaps, Gap{Code: "unresolved_runtime_dependency", File: file, Package: name, Message: name + ": no resolved runtime version; " + next})
			}
		}
	}
	for _, c := range inv.Components {
		if c.Version == nil {
			inv.CoverageGaps = append(inv.CoverageGaps, Gap{Code: "unknown_version", File: c.Source.File, Package: c.Name, Message: c.Name + ": installed version unknown; supply lockfile metadata with a resolved version"})
		}
	}
	sort.Slice(inv.Components, func(i, j int) bool { return inv.Components[i].PURL < inv.Components[j].PURL })
	return inv, nil
}
func (inv Inventory) Digest() (string, error) {
	b, e := json.Marshal(inv)
	if e != nil {
		return "", e
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
