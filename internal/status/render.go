package status

import (
	"bytes"
	"embed"
	"fmt"
	"html"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vincentsch/conformline/internal/inventory"
	"github.com/vincentsch/conformline/internal/version"
	"github.com/vincentsch/conformline/internal/vulns"
)

//go:embed report.html
var templates embed.FS

func ScanLabel(r Result) string {
	label := "no saved scan"
	if !r.ScannedAt.IsZero() {
		label = r.ScannedAt.Format("2006-01-02 15:04 UTC")
	}
	if r.ScanComplete {
		return label + ", complete"
	}
	return label + ", incomplete or stale"
}
func Terminal(w io.Writer, r Result) {
	fmt.Fprintf(w, "Conformline  %s %s (%s)   scan: %s\n\nNext\n", Value(r.Product.Name), Value(r.Product.Version), ProductType(r.Product.Type), ScanLabel(r))
	for i, a := range r.Next {
		if i == 3 {
			break
		}
		fmt.Fprintf(w, "  %d. %s\n", i+1, a)
	}
	if len(r.Next) == 0 {
		fmt.Fprintln(w, "  No outstanding actions.")
	}
	fmt.Fprint(w, "\nStatus"+"\n")
	for _, state := range []State{Evidenced, Review, Missing, NA} {
		names := []string{}
		for _, it := range r.Items {
			if it.State == state {
				name := it.Name
				if it.Name == "Open incidents" && it.Explanation == "none" {
					name += " (none)"
				}
				names = append(names, name)
			}
		}
		if len(names) > 0 {
			fmt.Fprintf(w, "  %-14s %s\n", state, strings.Join(names, ", "))
		}
	}
	for _, it := range r.Items {
		if it.Name == "SBOM" && it.State != Evidenced || it.Name == "Open incidents" && it.State != NA {
			fmt.Fprintln(w, "\n"+it.Explanation+" "+it.Action)
		}
	}
	for _, s := range r.ScanIssues {
		fmt.Fprintln(w, s)
	}
	for _, g := range r.CoverageGaps {
		fmt.Fprintln(w, "Coverage gap: "+g.Message)
	}
	for _, note := range r.Notes {
		fmt.Fprintln(w, note)
	}
	for _, it := range r.Items {
		if strings.Contains(it.Explanation, Assessment) || it.Name == "EU declaration of conformity" && it.State != NA {
			fmt.Fprintln(w, it.Explanation)
		}
	}
	if r.DryRun {
		fmt.Fprintln(w, "DRY RUN: would write status.md, status.html and cra/README.md")
	}
	fmt.Fprintln(w, "\nFull status: cra/reports/status.html\n"+Legal)
}
func md(s string) string {
	s = html.EscapeString(s)
	return strings.NewReplacer("|", "&#124;", "\n", "<br>", "\r", "", "[", "&#91;", "]", "&#93;", "`", "&#96;", "*", "&#42;", "_", "&#95;").Replace(s)
}
func Markdown(w io.Writer, r Result) {
	fmt.Fprintf(w, "# Conformline status\n\n%s %s (%s)\n\nScan: %s\n\n## Next steps\n\n", md(Value(r.Product.Name)), md(Value(r.Product.Version)), md(ProductType(r.Product.Type)), md(ScanLabel(r)))
	for i, a := range r.Next {
		fmt.Fprintf(w, "%d. %s\n", i+1, md(a))
	}
	fmt.Fprint(w, "\n## Checklist\n\n| State | Item | Explanation | Next action |\n| --- | --- | --- | --- |"+"\n")
	for _, it := range OrderedItems(r) {
		fmt.Fprintf(w, "| %s | %s | %s | %s |\n", it.State, md(it.Name), md(it.Explanation), md(it.Action))
	}
	fmt.Fprint(w, "\n## Scan evidence\n"+"\n")
	for _, s := range r.ScanIssues {
		fmt.Fprintln(w, md(s))
	}
	fmt.Fprint(w, "\n## Coverage gaps\n"+"\n")
	for _, g := range r.CoverageGaps {
		fmt.Fprintln(w, "- "+md(g.Message))
	}
	for _, shipped := range []bool{true, false} {
		heading := "Shipped and possibly shipped components"
		if !shipped {
			heading = "Non-shipped findings"
		}
		fmt.Fprintln(w, "\n## "+heading+"\n\n| Component | Version | Shipped | Where found | Advisories |\n| --- | --- | --- | --- | --- |")
		for _, c := range r.Components {
			if Shipped(c) != "not shipped" != shipped {
				continue
			}
			fmt.Fprintf(w, "| %s | %s | %s | %s | %d |\n", md(c.Name), md(Value(c.Version)), Shipped(c), md(Paths(c)), Count(r, c))
		}
		for _, f := range r.Findings {
			if (Shipped(f.Component) != "not shipped") != shipped {
				continue
			}
			fmt.Fprintf(w, "\n### %s: %s\n\n%s; %s\n\n", md(f.Component.Name), md(strings.Join(f.IDs, ", ")), md(f.Status), Known(f))
			if f.Decision != nil {
				fmt.Fprintln(w, md(Value(f.Decision.Reason)))
			}
			for _, a := range f.Advisories {
				fmt.Fprintf(w, "\n%s: %s. Severity: %s. Fixed versions: %s.\n", md(a.ID), md(a.Summary), md(vulns.Rating(a, f.Component)), md(strings.Join(vulns.Fixed(a, f.Component), ", ")))
				for _, ref := range a.References {
					fmt.Fprintln(w, md(ref.URL))
				}
			}
		}
	}
	fmt.Fprint(w, "\n## Documents\n\n| File | Status | Reviewed by | Reviewed on |\n| --- | --- | --- | --- |"+"\n")
	for _, d := range r.Documents {
		fmt.Fprintf(w, "| %s | %s (%s) | %s | %s |\n", md(d.Path), md(d.Status), d.State, md(d.ReviewedBy), md(d.ReviewedOn))
	}
	fmt.Fprint(w, "\n## Notes\n"+"\n")
	for _, s := range r.Notes {
		fmt.Fprintln(w, md(s))
	}
	fmt.Fprintln(w, "\nConformline "+version.Version+". Data sources: OSV.dev; GitHub Advisory Database (CC-BY 4.0); CISA KEV.\n\n"+Legal)
}
func Shipped(c inventory.Component) string {
	if c.Shipped == nil {
		return "possibly shipped"
	}
	if *c.Shipped {
		return "shipped"
	}
	return "not shipped"
}
func Paths(c inventory.Component) string {
	out := []string{}
	for _, e := range c.Evidence {
		out = append(out, e.Path)
	}
	return strings.Join(out, ", ")
}
func Count(r Result, c inventory.Component) int {
	n := 0
	for _, f := range r.Findings {
		if f.Component.PURL == c.PURL {
			n++
		}
	}
	return n
}
func Known(f vulns.Finding) string {
	if f.KnownExploited {
		return "known exploited (CISA KEV)"
	}
	return "not listed in CISA KEV"
}
func OrderedItems(r Result) []Item {
	out := []Item{}
	for _, state := range []State{Evidenced, Review, Missing, NA} {
		for _, it := range r.Items {
			if it.State == state {
				out = append(out, it)
			}
		}
	}
	return out
}
func HTML(w io.Writer, r Result) error {
	t, e := template.New("report.html").Funcs(template.FuncMap{"toolVersion": func() string { return version.Version }, "productType": ProductType, "slice": func(values ...string) []string { return values }, "value": Value, "scan": ScanLabel, "items": OrderedItems, "paths": Paths, "shipped": Shipped, "count": func(c inventory.Component) int { return Count(r, c) }, "findings": func(c inventory.Component) []vulns.Finding {
		out := []vulns.Finding{}
		for _, f := range r.Findings {
			if f.Component.PURL == c.PURL {
				out = append(out, f)
			}
		}
		return out
	}, "rating": vulns.Rating, "fixed": vulns.Fixed, "join": func(s []string) string { return strings.Join(s, ", ") }, "known": Known, "legal": func() string { return Legal }}).ParseFS(templates, "report.html")
	if e != nil {
		return e
	}
	return t.Execute(w, r)
}
func Write(root string, r Result) error {
	var markdown, html bytes.Buffer
	Markdown(&markdown, r)
	if e := HTML(&html, r); e != nil {
		return e
	}
	for _, f := range []struct {
		path string
		b    []byte
	}{{"cra/reports/status.md", markdown.Bytes()}, {"cra/reports/status.html", html.Bytes()}} {
		if e := replace(root, f.path, f.b); e != nil {
			return e
		}
	}
	return nil
}
func replace(root, file string, b []byte) error {
	path := filepath.Join(root, file)
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		return fmt.Errorf("cannot create %s; check project permissions", file)
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".status-*")
	if e != nil {
		return fmt.Errorf("cannot write %s; check project permissions", file)
	}
	defer os.Remove(f.Name())
	_, e = f.Write(b)
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Chmod(f.Name(), 0644)
	}
	if e == nil {
		e = os.Rename(f.Name(), path)
	}
	if e != nil {
		return fmt.Errorf("cannot replace %s; check permissions and free space", file)
	}
	return nil
}

func ProductType(kind string) string {
	labels := map[string]string{"wordpress-plugin": "WordPress plugin", "wordpress-theme": "WordPress theme", "composer-package": "Composer package", "npm-package": "npm package", "application": "Application", "other": "Product"}
	if label := labels[kind]; label != "" {
		return label
	}
	return kind
}
