package inventory

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/vincentsch/fendkit/internal/detect"
	"github.com/vincentsch/fendkit/internal/profile"
)

// ReleaseError identifies a failure while reading the selected release.
type ReleaseError struct{ Err error }

func (e *ReleaseError) Error() string { return e.Err.Error() }
func (e *ReleaseError) Unwrap() error { return e.Err }

type Options struct {
	Release       *string
	ReplayRelease bool
	Profile       *profile.Profile
}

func Build(root string, product detect.Product) (Inventory, error) {
	return BuildWithOptions(root, product, Options{})
}

func ProductPURL(root string, p detect.Product) string {
	absolute, e := filepath.Abs(root)
	if e != nil {
		absolute = filepath.Clean(root)
	}
	name := filepath.Base(absolute)
	eco := "generic"
	switch p.Type {
	case "composer-package", "npm-package":
		eco = "composer"
		if p.Type == "npm-package" {
			eco = "npm"
		}
		if p.PackageName != "" {
			name = p.PackageName
		} else if p.Name != nil {
			name = *p.Name
		}
	default:
		if !strings.HasPrefix(p.Type, "wordpress-") && p.Name != nil {
			name = *p.Name
		}
		name = strings.Trim(regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(name), "-"), "-")
		if name == "" {
			name = "product"
		}
	}
	version := ""
	if p.Version != nil && *p.Version != "unknown" {
		version = *p.Version
	}
	return PURL(eco, name, version)
}

func selectRelease(root string, p *detect.Product, opts Options) (*string, error) {
	selected := opts.Release
	if opts.ReplayRelease && selected == nil {
		return nil, nil
	}
	if selected == nil && opts.Profile != nil {
		selected = opts.Profile.Product.Release
	}
	if selected != nil {
		s := *selected
		if strings.Contains(s, "{version}") {
			if p.Version == nil {
				p.Notes = append(p.Notes, "Release pattern needs product.version; set it in cra.yml")
				return nil, nil
			}
			s = strings.ReplaceAll(s, "{version}", *p.Version)
		}
		if strings.TrimSpace(s) == "" {
			return nil, fmt.Errorf("release path is empty; set product.release or --release to a ZIP or folder")
		}
		return &s, nil
	}
	if p.Version == nil {
		p.Notes = append(p.Notes, "Release discovery needs product.version; set it in cra.yml")
		return nil, nil
	}
	candidates := []string{}
	for _, dir := range []string{"dist", "build"} {
		entries, e := os.ReadDir(filepath.Join(root, dir))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return nil, fmt.Errorf("%s: cannot discover release; check permissions", dir)
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.EqualFold(filepath.Ext(entry.Name()), ".zip") && strings.Contains(entry.Name(), *p.Version) {
				candidates = append(candidates, path.Join(dir, entry.Name()))
			}
		}
	}
	if len(candidates) == 1 {
		return &candidates[0], nil
	}
	if len(candidates) > 1 {
		p.Notes = append(p.Notes, "Several release ZIPs match: "+strings.Join(candidates, ", ")+"; select one with --release or product.release")
	}
	return nil, nil
}

// ValidateRelease checks an interview answer before it becomes a saved release boundary.
func ValidateRelease(root string, product detect.Product, path string) error {
	selected, err := selectRelease(root, &product, Options{Release: &path})
	if err != nil {
		return err
	}
	if selected == nil {
		return fmt.Errorf("release pattern needs product.version; use a literal release path while the version is unknown")
	}
	tree, close, err := openRelease(root, *selected)
	if err != nil {
		return err
	}
	defer close()
	return releaseProduct(tree, product)
}

func openRelease(root, selected string) (fs.FS, func(), error) {
	filename := selected
	if !filepath.IsAbs(filename) {
		filename = filepath.Join(root, filename)
	}
	info, e := os.Stat(filename)
	if e != nil {
		return nil, nil, fmt.Errorf("release %s is missing or unreadable; correct --release or product.release and check permissions", filepath.ToSlash(selected))
	}
	var tree fs.FS
	close := func() {}
	if info.IsDir() {
		tree = os.DirFS(filename)
	} else {
		z, e := zip.OpenReader(filename)
		if e != nil {
			return nil, nil, fmt.Errorf("release %s is not a readable ZIP; supply a ZIP or folder", filepath.ToSlash(selected))
		}
		tree = z
		close = func() { _ = z.Close() }
	}
	entries, e := fs.ReadDir(tree, ".")
	if e != nil {
		close()
		return nil, nil, fmt.Errorf("release is unreadable; check its permissions")
	}
	if len(entries) == 1 && entries[0].IsDir() {
		tree, e = fs.Sub(tree, entries[0].Name())
		if e != nil {
			close()
			return nil, nil, e
		}
	}
	return tree, close, nil
}

func readLimited(tree fs.FS, file string, limit int64) ([]byte, error) {
	f, e := tree.Open(file)
	if e != nil {
		return nil, fmt.Errorf("%s: cannot read; check permissions", file)
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit))
	if e != nil {
		return nil, fmt.Errorf("%s: cannot read file content", file)
	}
	return b, nil
}

func releaseProduct(tree fs.FS, p detect.Product) error {
	entries, e := fs.ReadDir(tree, ".")
	if e != nil {
		return e
	}
	versions := []string{}
	for _, entry := range entries {
		file := entry.Name()
		check := false
		key := ""
		switch p.Type {
		case "wordpress-plugin":
			check = strings.HasSuffix(file, ".php")
			key = "Plugin Name"
		case "wordpress-theme":
			check = file == "style.css"
			key = "Theme Name"
		case "composer-package":
			check = file == "composer.json"
		case "npm-package":
			check = file == "package.json"
		}
		if !check || entry.IsDir() {
			continue
		}
		b, e := readLimited(tree, file, 2<<20)
		if e != nil {
			return e
		}
		version := ""
		if key != "" {
			if !regexp.MustCompile(`(?mi)^[\s/*#]*` + key + `:`).Match(b) {
				continue
			}
			m := regexp.MustCompile(`(?mi)^[\s/*#]*Version:\s*([^\r\n*]+)`).FindSubmatch(b)
			if m != nil {
				version = strings.TrimSpace(string(m[1]))
			}
		} else {
			var m struct{ Version string }
			if json.Unmarshal(b, &m) != nil {
				return fmt.Errorf("release %s: invalid manifest JSON; rebuild the release", file)
			}
			version = m.Version
		}
		if version != "" {
			versions = append(versions, version)
		}
	}
	for _, v := range versions {
		if p.Version != nil && v != *p.Version {
			return fmt.Errorf("release version %s differs from project version %s; rebuild the release or correct product.version and --release", v, *p.Version)
		}
	}
	return nil
}

// npmRoot finds the nearest package directory, including scoped and nested installs.
func npmRoot(file string) (string, string) {
	parts := strings.Split(file, "/")
	for i := len(parts) - 2; i >= 0; i-- {
		if parts[i] != "node_modules" || i+1 >= len(parts) {
			continue
		}
		end := i + 2
		name := parts[i+1]
		if name == "." || name == "" {
			continue
		}
		if strings.HasPrefix(name, "@") {
			if end >= len(parts) || parts[end] == "." || parts[end] == "" {
				continue
			}
			name += "/" + parts[end]
			end++
		}
		return strings.Join(parts[:end], "/"), name
	}
	return "", ""
}

func scanTree(tree fs.FS, release bool, repository []Component) ([]Component, error) {
	files := []string{}
	roots := map[string]string{}
	e := fs.WalkDir(tree, ".", func(file string, d fs.DirEntry, e error) error {
		if e != nil {
			return fmt.Errorf("%s: cannot read directory; check permissions", file)
		}
		if d.IsDir() {
			if dir, name := npmRoot(file + "/."); dir != "" {
				roots[dir] = name
			}
			if d.Name() == ".git" || (!release && (file == "cra" || file == "dist" || file == "build")) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		files = append(files, file)
		return nil
	})
	if e != nil {
		return nil, e
	}
	out := []Component{}
	identified := map[string]bool{}
	matched := map[string]bool{}
	for _, file := range files {
		dir, name := npmRoot(file)
		if dir != "" {
			roots[dir] = name
		}
		if dir == "" || file != dir+"/package.json" {
			continue
		}
		identified[dir] = true
		if !release {
			continue
		}
		b, e := readLimited(tree, file, 2<<20)
		if e != nil {
			return nil, e
		}
		var m struct{ Name, Version string }
		if json.Unmarshal(b, &m) != nil {
			return nil, fmt.Errorf("%s: invalid npm metadata; rebuild the release", file)
		}
		if m.Name != "" {
			name = m.Name
		}
		c := component("npm", name, m.Version, false, Evidence{File: file, Method: "package.json", Path: dir})
		c.Shipped = boolPtr(true)
		c.Evidence[0].Shipped = c.Shipped
		out = append(out, c)
	}
	for _, file := range files {
		if release && strings.HasSuffix(file, "composer/installed.json") {
			b, e := readLimited(tree, file, 16<<20)
			if e != nil {
				return nil, e
			}
			cs, e := Installed(b, file)
			if e != nil {
				return nil, e
			}
			for _, c := range cs {
				c.Shipped = boolPtr(true)
				c.Development = false
				c.Evidence[0].Shipped = c.Shipped
				out = append(out, c)
			}
		}
		if !strings.EqualFold(path.Ext(file), ".js") {
			continue
		}
		dir, _ := npmRoot(file)
		if identified[dir] {
			continue
		}
		b, e := readLimited(tree, file, maxJS)
		if e != nil {
			return nil, e
		}
		cs := BundledJS(b, file)
		if !release {
			// Use the nearest Composer package's classification, including custom install paths.
			development, closest := false, 0
			for _, owner := range repository {
				if owner.Ecosystem != "composer" {
					continue
				}
				for _, ev := range owner.Evidence {
					prefix := strings.TrimSuffix(ev.Path, "/") + "/"
					if strings.HasPrefix(file, prefix) && len(prefix) > closest {
						development = owner.Development
						closest = len(prefix)
					}
				}
			}
			if development {
				for i := range cs {
					cs[i].Development = true
					cs[i].Shipped = boolPtr(false)
					cs[i].Source.Shipped = cs[i].Shipped
					cs[i].Evidence[0].Shipped = cs[i].Shipped
				}
			}
		}
		if len(cs) > 0 {
			matched[dir] = true
		}
		out = append(out, cs...)
	}
	if release {
		dirs := []string{}
		for dir := range roots {
			dirs = append(dirs, dir)
		}
		sort.Strings(dirs)
		for _, dir := range dirs {
			if identified[dir] || matched[dir] {
				continue
			}
			c := component("npm", roots[dir], "", false, Evidence{File: dir, Method: "node_modules folder", Path: dir})
			c.Shipped = boolPtr(true)
			c.Evidence[0].Shipped = c.Shipped
			out = append(out, c)
		}
	}
	return out, nil
}

func BuildWithOptions(root string, p detect.Product, opts Options) (Inventory, error) {
	if opts.Profile != nil {
		pp := opts.Profile.Product
		if pp.Name != nil {
			p.Name = pp.Name
		}
		if pp.Type != nil {
			p.Type = *pp.Type
		}
		if pp.Version != nil {
			p.Version = pp.Version
		}
	}
	p.PURL = ProductPURL(root, p)
	selected, e := selectRelease(root, &p, opts)
	if e != nil {
		return Inventory{}, e
	}
	inv, e := buildMetadata(root, p)
	if e != nil {
		return inv, e
	}
	repo, e := scanTree(os.DirFS(root), false, inv.Components)
	if e != nil {
		return inv, e
	}
	all := []Component{}
	for _, c := range inv.Components {
		for _, ev := range c.Evidence {
			occurrence := c
			occurrence.Source = ev
			occurrence.Evidence = []Evidence{ev}
			occurrence.Shipped = ev.Shipped
			all = append(all, occurrence)
		}
	}
	all = append(all, repo...)
	if selected != nil {
		tree, close, e := openRelease(root, *selected)
		if e != nil {
			return inv, &ReleaseError{Err: e}
		}
		defer close()
		if e = releaseProduct(tree, p); e != nil {
			return inv, &ReleaseError{Err: e}
		}
		cs, e := scanTree(tree, true, nil)
		if e != nil {
			return inv, &ReleaseError{Err: e}
		}
		absolute := *selected
		if !filepath.IsAbs(absolute) {
			absolute = filepath.Join(root, absolute)
		}
		absolute, e = filepath.Abs(absolute)
		if e != nil {
			return inv, e
		}
		base, e := filepath.Abs(root)
		if e != nil {
			return inv, e
		}
		rel := filepath.ToSlash(RelativeOrAbsolute(base, absolute))
		inv.Release = &rel
		for i := range all {
			c := &all[i]
			if c.Ecosystem == "composer" || c.Source.Method == "bundled JavaScript" {
				c.Shipped = boolPtr(false)
				c.Evidence[0].Shipped = c.Shipped
			}
		}
		for _, c := range cs {
			c.Source.Method = "release " + c.Source.Method
			c.Evidence[0].Method = c.Source.Method
			all = append(all, c)
		}
	}
	if opts.Profile != nil {
		all, e = applyManual(all, opts.Profile.Components)
		if e != nil {
			return inv, e
		}
	}
	inv.Components = mergeComponents(all)
	gaps := []Gap{}
	for _, gap := range inv.CoverageGaps {
		if gap.Code == "unknown_version" {
			continue
		}
		if gap.Code == "unresolved_runtime_dependency" {
			resolved := false
			for _, c := range inv.Components {
				if c.Name == gap.Package && c.Version != nil && !c.Development && ((gap.File == "composer.json" && c.Ecosystem == "composer") || (gap.File == "package.json" && c.Ecosystem == "npm")) {
					resolved = true
				}
			}
			if resolved {
				continue
			}
		}
		gaps = append(gaps, gap)
	}
	for _, c := range inv.Components {
		if c.Ecosystem != "composer" && c.Ecosystem != "npm" {
			gaps = append(gaps, Gap{Code: "unsupported_advisory_ecosystem", File: c.Source.File, Package: c.Name, Message: c.Name + ": advisory lookups are not available for this component; review its upstream security information"})
		}
		if c.Version == nil {
			gaps = append(gaps, Gap{Code: "unknown_version", File: c.Source.File, Package: c.Name, Message: c.Name + ": version unknown; confirm it with a manual components entry in cra.yml"})
		}
	}
	inv.CoverageGaps = gaps
	return inv, nil
}

func applyManual(all []Component, manual []profile.Component) ([]Component, error) {
	for i, m := range manual {
		found := false
		update := func(c Component) Component {
			if m.Name != nil {
				c.Name = *m.Name
			}
			if m.Ecosystem != nil {
				c.Ecosystem = *m.Ecosystem
			}
			if m.Version != nil {
				c.Version = detect.String(*m.Version)
				c.LookupVersion = detect.String(strings.TrimPrefix(*m.Version, "v"))
				c.Modified = false
				if strings.HasPrefix(c.Note, "Based on ") {
					c.Note = ""
				}
				if match := releaseVersion.FindStringSubmatch(*m.Version); match != nil && match[2] != "" && !strings.HasPrefix(match[2], "+") && !prerelease.MatchString(match[2]) && strings.Contains(c.Source.Method, "bundled JavaScript") {
					c.Modified = true
					c.LookupVersion = detect.String(match[1])
					c.Note = "Based on " + match[1] + "; this is a modified copy, check whether the fix is in"
				}
			}
			version := ""
			if c.Version != nil {
				version = *c.Version
			}
			c.PURL = PURL(c.Ecosystem, c.Name, version)
			if m.PURL != nil {
				c.PURL = *m.PURL
			}
			if m.Shipped != nil {
				c.Shipped = m.Shipped
			}
			if c.Shipped != nil && *c.Shipped {
				c.Development = false
			}
			if m.Note != nil {
				c.Note = *m.Note
			}
			c.Evidence[0].Shipped = c.Shipped
			if c.Ecosystem != "composer" && c.Ecosystem != "npm" {
				c.LookupVersion = nil
			}
			c.Source.Shipped = c.Shipped
			c.Evidence = append(c.Evidence, Evidence{File: "cra.yml", Method: "manual correction", Path: c.Source.Path, Shipped: c.Shipped})
			return c
		}
		if m.Path != nil {
			for j, c := range all {
				if c.Source.Path == *m.Path {
					all[j] = update(c)
					found = true
				}
			}
			if !found {
				return nil, fmt.Errorf("components[%d].path: no detected occurrence at %s; correct the path or omit it to add a component", i, *m.Path)
			}
		} else {
			if m.Name == nil || m.Ecosystem == nil {
				return nil, fmt.Errorf("components[%d]: name and ecosystem are required when adding a component", i)
			}
			c := component(*m.Ecosystem, *m.Name, "", false, Evidence{File: "cra.yml", Method: "manual component"})
			all = append(all, update(c))
		}
	}
	return all, nil
}

func mergeComponents(all []Component) []Component {
	out := []Component{}
	indices := map[string]int{}
	for _, c := range all {
		c.Source.Shipped = c.Evidence[0].Shipped
		i, ok := indices[c.PURL]
		if !ok {
			indices[c.PURL] = len(out)
			out = append(out, c)
			continue
		}
		old := &out[i]
		old.Evidence = append(old.Evidence, c.Evidence...)
		old.Development = old.Development && c.Development
		if (old.Shipped != nil && *old.Shipped) || (c.Shipped != nil && *c.Shipped) {
			old.Shipped = boolPtr(true)
		} else if old.Shipped == nil || c.Shipped == nil {
			old.Shipped = nil
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PURL < out[j].PURL })
	return out
}
