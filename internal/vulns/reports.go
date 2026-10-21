package vulns

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vincentsch/fendkit/internal/profile"
)

func text(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ", "`", "'", "<", "&lt;", ">", "&gt;").Replace(s)
}
func Markdown(r Report) []byte {
	var b bytes.Buffer
	state := "complete"
	if !r.Complete {
		state = "incomplete"
	}
	fmt.Fprintf(&b, "# Known vulnerabilities\n\nScan %s is **%s**. Scanned at %s.\n\n", r.ScanID, state, r.ScannedAt.Format(time.RFC3339))
	version := "unknown"
	if r.ProductVersion != nil {
		version = *r.ProductVersion
	}
	fmt.Fprintf(&b, "Product version: %s. Inventory digest: `%s`.\n\n", text(version), r.InventoryDigest)
	for _, reason := range r.Reason {
		fmt.Fprintf(&b, "- %s\n", text(reason))
	}
	shipped, unknown, notShipped := 0, 0, 0
	for _, f := range r.Findings {
		if f.Component.Shipped == nil {
			unknown++
		} else if *f.Component.Shipped {
			shipped++
		} else {
			notShipped++
		}
	}
	fmt.Fprintf(&b, "\n%d advisory groups in shipped components, %d in possibly shipped components, %d in not shipped components.\n\nA scan without findings does not prove the absence of vulnerabilities. Only third-party components are checked.\n", shipped, unknown, notShipped)
	for _, section := range []string{"Shipped", "Possibly shipped", "Not shipped"} {
		fmt.Fprintf(&b, "\n## %s\n", section)
		last := ""
		count := 0
		for _, f := range r.Findings {
			group := "Possibly shipped"
			if f.Component.Shipped != nil {
				if *f.Component.Shipped {
					group = "Shipped"
				} else {
					group = "Not shipped"
				}
			}
			if group != section {
				continue
			}
			count++
			c := f.Component
			if c.PURL != last {
				fmt.Fprintf(&b, "\n### %s\n\nComponent: `%s`\n\n%s\n", text(c.Name), text(c.PURL), text(Advice(c, r.Findings)))
				for _, ev := range c.Evidence {
					fmt.Fprintf(&b, "\n- `%s` (%s, %s)\n", text(ev.Path), text(ev.File), text(ev.Method))
				}
				if c.Note != "" {
					fmt.Fprintf(&b, "\n%s\n", text(c.Note))
				}
				last = c.PURL
			}
			fmt.Fprintf(&b, "\n#### %s\n\nStatus: %s.", strings.Join(f.IDs, ", "), f.Status)
			if f.KnownExploited {
				fmt.Fprint(&b, " **Known exploited (CISA KEV).**")
			}
			fmt.Fprintln(&b)
			if f.Decision != nil {
				fmt.Fprintf(&b, "\nReason: %s\n", text(*f.Decision.Reason))
			}
			for _, a := range f.Advisories {
				fixes := strings.Join(Fixed(a, c), ", ")
				if fixes == "" {
					fixes = "no fixed version supplied"
				}
				fmt.Fprintf(&b, "\n- [%s](https://osv.dev/vulnerability/%s): %s. Severity: %s. Published: %s. Fixes: %s.\n", text(a.ID), a.ID, text(a.Summary), text(Rating(a, c)), text(a.Published), text(fixes))
				for _, ref := range a.References {
					if strings.HasPrefix(ref.URL, "https://") || strings.HasPrefix(ref.URL, "http://") {
						fmt.Fprintf(&b, "  - <%s>\n", text(ref.URL))
					}
				}
			}
		}
		if count == 0 {
			fmt.Fprintln(&b, "\nNo findings saved for this group.")
		}
	}
	fmt.Fprint(&b, "\n## Coverage gaps\n")
	if len(r.CoverageGaps) == 0 {
		fmt.Fprintln(&b, "\nNo inventory coverage gaps recorded.")
	}
	for _, g := range r.CoverageGaps {
		fmt.Fprintf(&b, "\n- %s\n", text(g.Message))
	}
	fmt.Fprint(&b, "\n## Sources\n\nAdvisory data: [OSV.dev](https://osv.dev/).\nKnown exploited vulnerabilities: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).\n")
	ghsa := false
	for _, f := range r.Findings {
		for _, id := range f.IDs {
			if strings.HasPrefix(id, "GHSA-") {
				ghsa = true
			}
		}
	}
	if ghsa {
		fmt.Fprint(&b, "GitHub advisory data: [GitHub Advisory Database](https://github.com/advisories), [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/).\n")
	}
	return b.Bytes()
}
func VEX(r Report, p *profile.Profile) ([]byte, error) {
	statements := []any{}
	for _, f := range r.Findings {
		if f.Decision == nil {
			continue
		}
		t := f.Decision
		if err := profile.ValidateTriage(*t); err != nil {
			return nil, err
		}
		statement := map[string]any{"vulnerability": map[string]any{"name": f.Advisories[0].ID, "aliases": f.IDs}, "products": []any{map[string]any{"@id": r.ProductPURL, "subcomponents": []any{map[string]any{"@id": f.Component.PURL}}}}, "status": *t.Status, "status_notes": *t.Reason}
		switch *t.Status {
		case "affected":
			statement["action_statement"] = *t.Reason
		case "not_affected":
			statement["justification"] = *t.Justification
			statement["impact_statement"] = *t.Reason
		}
		statements = append(statements, statement)
	}
	if len(statements) == 0 {
		return nil, nil
	}
	if p == nil || p.Manufacturer.Name == nil || strings.TrimSpace(*p.Manufacturer.Name) == "" {
		return nil, fmt.Errorf("set manufacturer.name in cra.yml to author the VEX statements")
	}
	doc := map[string]any{"@context": "https://openvex.dev/ns/v0.2.0", "author": *p.Manufacturer.Name, "timestamp": r.ScannedAt.Format(time.RFC3339), "version": 1, "statements": statements}
	payload, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	doc["@id"] = "https://openvex.dev/docs/public/vex-" + hex.EncodeToString(digest[:])
	return json.MarshalIndent(doc, "", "  ")
}
func Write(root string, r Report, p *profile.Profile) error {
	vex, err := VEX(r, p)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Join(root, "cra", "reports")
	if err = os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("cannot create cra/reports; check project permissions")
	}
	for _, file := range []struct {
		name string
		data []byte
	}{{"vulnerabilities.json", append(data, '\n')}, {"vulnerabilities.md", Markdown(r)}, {"vex.openvex.json", vex}} {
		if len(file.data) == 0 {
			if err = os.Remove(filepath.Join(dir, file.name)); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("cannot remove obsolete %s; check cra/reports permissions", file.name)
			}
			continue
		}
		if err = replace(dir, file.name, file.data); err != nil {
			return err
		}
	}
	return nil
}
func replace(dir, name string, b []byte) error {
	f, err := os.CreateTemp(dir, ".report-*")
	if err != nil {
		return fmt.Errorf("cannot write %s; check cra/reports permissions", name)
	}
	defer os.Remove(f.Name())
	_, err = f.Write(b)
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), filepath.Join(dir, name))
	}
	if err != nil {
		return fmt.Errorf("cannot replace %s; check cra/reports permissions", name)
	}
	return nil
}
