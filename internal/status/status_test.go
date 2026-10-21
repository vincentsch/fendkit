package status

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincentsch/fendkit/internal/detect"
	"github.com/vincentsch/fendkit/internal/docs"
	"github.com/vincentsch/fendkit/internal/inventory"
	"github.com/vincentsch/fendkit/internal/profile"
	"github.com/vincentsch/fendkit/internal/sbom"
	"github.com/vincentsch/fendkit/internal/vulns"
)

var frozenTime = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func put(t *testing.T, root, file, text string) {
	t.Helper()
	path := filepath.Join(root, file)
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte(text), 0644); e != nil {
		t.Fatal(e)
	}
}
func writeJSON(t *testing.T, root, file string, v any) {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	put(t, root, "cra/reports/"+file, string(b))
}
func fixture(t *testing.T) (string, *profile.Profile, Scan, vulns.Report) {
	t.Helper()
	root := t.TempDir()
	put(t, root, "package.json", `{"name":"sample","version":"1.0.0"}`)
	p := &profile.Profile{Version: 1, Role: profile.Role{Answer: "manufacturer"}, Classification: profile.Classification{Answer: "default"}, Support: profile.Support{End: detect.String("2031-10-20")}}
	product, e := detect.Detect(root)
	if e != nil {
		t.Fatal(e)
	}
	inv, e := inventory.BuildWithOptions(root, product, inventory.Options{Profile: p})
	if e != nil {
		t.Fatal(e)
	}
	digest, _ := inv.Digest()
	saved := Scan{ScanID: "frozen-scan", ScannedAt: frozenTime, ProductVersion: inv.Product.Version, InventoryDigest: digest, Complete: true, Inventory: inv}
	vr := vulns.Report{ScanID: saved.ScanID, ScannedAt: frozenTime, ProductVersion: saved.ProductVersion, ProductPURL: inv.Product.PURL, InventoryDigest: digest, Complete: true}
	saveEvidence(t, root, saved, vr)
	for _, file := range docs.Files {
		body := "---\nstatus: reviewed\nreviewed_by: Maker\nreviewed_on: 2026-10-20\n---\nContact: security@example.com\n"
		if strings.HasSuffix(file, "security.txt") {
			body = "# status: reviewed\n# reviewed_by: Maker\n# reviewed_on: 2026-10-20\nContact: mailto:security@example.com\nExpires: 2027-10-19T12:00:00Z\n"
		}
		put(t, root, file, body)
	}
	return root, p, saved, vr
}
func saveEvidence(t *testing.T, root string, s Scan, v vulns.Report) {
	t.Helper()
	writeJSON(t, root, "inventory.json", s)
	writeJSON(t, root, "vulnerabilities.json", v)
	bom := sbom.New(s.Inventory, nil, sbom.Provenance{ScanID: s.ScanID, ScannedAt: s.ScannedAt, InventoryDigest: s.InventoryDigest, Complete: s.Complete}, "0.1.0")
	var b bytes.Buffer
	if e := sbom.Write(&b, bom); e != nil {
		t.Fatal(e)
	}
	put(t, root, "cra/reports/sbom.cdx.json", b.String())
}
func evaluate(t *testing.T, root string, p *profile.Profile, strict bool) Result {
	t.Helper()
	r, e := Evaluate(root, p, frozenTime, strict)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestChecklistEvidenceAndRoles(t *testing.T) {
	for _, role := range []string{"manufacturer", "open-source-steward", "unknown", "not-in-scope"} {
		t.Run(role, func(t *testing.T) {
			root, p, _, _ := fixture(t)
			p.Role.Answer = role
			r := evaluate(t, root, p, true)
			if r.ExitCode != 0 || len(r.Items) != 13 {
				t.Fatalf("%+v", r)
			}
			for i, it := range r.Items {
				want := Evidenced
				if i == 12 || role == "not-in-scope" && i != 0 && i != 4 && i != 5 {
					want = NA
				}
				if role == "unknown" && i == 0 {
					want = Review
				}
				if it.State != want {
					t.Errorf("%s: %s want %s", it.Name, it.State, want)
				}
			}
			if role == "unknown" && !strings.Contains(r.Next[0], "role.answer") {
				t.Fatal(r.Next)
			}
		})
	}
	for _, class := range []string{"unknown", "important-class-i", "important-class-ii", "critical"} {
		t.Run(class, func(t *testing.T) {
			root, p, _, _ := fixture(t)
			p.Classification.Answer = class
			r := evaluate(t, root, p, false)
			if class == "unknown" {
				if r.Items[1].State != Review {
					t.Fatal(r.Items[1])
				}
			} else {
				for _, i := range []int{1, 10} {
					if !strings.Contains(r.Items[i].Explanation, Assessment) || !strings.Contains(r.Items[i].Explanation, AssessmentURL) {
						t.Fatal(r.Items[i])
					}
				}
			}
		})
	}
}
func TestEveryDocumentState(t *testing.T) {
	for _, file := range docs.Files {
		for _, state := range []State{Missing, Review, Evidenced} {
			t.Run(file+"/"+string(state), func(t *testing.T) {
				root, p, _, _ := fixture(t)
				switch state {
				case Missing:
					os.Remove(filepath.Join(root, file))
				case Review:
					put(t, root, file, "Existing file without metadata.")
				}
				r := evaluate(t, root, p, false)
				index := map[string]int{"SECURITY.md": 2, "cra/security.txt": 2, "cra/disclosure-policy.md": 3, "cra/support-period.md": 6, "cra/user-information.md": 7, "cra/risk-assessment.md": 8, "cra/technical-documentation.md": 9, "cra/eu-declaration-of-conformity.md": 10, "cra/incident-checklist.md": 11}[file]
				if r.Items[index].State != state {
					t.Fatal(r.Items[index])
				}
				if state == Missing && evaluate(t, root, p, true).ExitCode != 10 {
					t.Fatal("strict must fail missing item")
				}
			})
		}
	}
	for _, body := range []string{"---\nstatus: reviewed\nreviewed_by: ''\nreviewed_on: 2026-10-20\n---\nDone", "---\nstatus: reviewed\nreviewed_by: Maker\nreviewed_on: yesterday\n---\nDone", "---\nstatus: reviewed\nreviewed_by: Maker\nreviewed_on: 2026-10-20\n---\n[[fill]]"} {
		root, _, _, _ := fixture(t)
		put(t, root, "cra/user-information.md", body)
		if InspectDocument(root, "cra/user-information.md", frozenTime).State != Review {
			t.Fatal(body)
		}
	}
	root, p, _, _ := fixture(t)
	p.Support.End = nil
	if evaluate(t, root, p, false).Items[6].State != Missing {
		t.Fatal("missing support date")
	}
	for _, body := range []string{"# status: reviewed\n# reviewed_by: Maker\n# reviewed_on: 2026-10-20\nContact: mailto:security@example.com\nExpires: 2025-01-01T00:00:00Z", "# status: reviewed\n# reviewed_by: Maker\n# reviewed_on: 2026-10-20\nContact: invalid\nExpires: 2027-01-01T00:00:00Z"} {
		put(t, root, "cra/security.txt", body)
		if evaluate(t, root, p, false).Items[2].State != Review {
			t.Fatal(body)
		}
	}
}
func finding(name, label string, shipped bool) vulns.Finding {
	c := inventory.Component{Name: name, Version: detect.String("1.0.0"), LookupVersion: detect.String("1.0.0"), PURL: "pkg:npm/" + name + "@1.0.0", Ecosystem: "npm", Shipped: &shipped, Evidence: []inventory.Evidence{{Path: "assets/js/vendor/" + name + ".js"}}}
	a := vulns.Advisory{ID: "GHSA-" + name, Summary: "Fix <b>markup</b> & review", Affected: []vulns.Affected{{Package: vulns.Package{Name: name, Ecosystem: "npm"}, Ranges: []vulns.Range{{Type: "SEMVER", Events: []vulns.Event{{Introduced: "0"}, {Fixed: "1.0.1"}}}}}}}
	a.DatabaseSpecific.Severity = label
	return vulns.Finding{IDs: []string{a.ID}, Component: c, Advisories: []vulns.Advisory{a}, Status: "untriaged"}
}
func TestScanEvidenceAndPolicyPrecedence(t *testing.T) {
	for _, scenario := range []string{"missing inventory", "missing vulnerabilities", "missing sbom", "mixed vulnerabilities", "mixed sbom", "wrong sbom version", "changed inventory", "changed version", "expired", "incomplete", "coverage", "offline", "digest mismatch", "missing metadata", "unreadable inventory", "release missing", "expired release missing", "offline release missing", "source error", "source error with release", "source and release error", "incomplete and changed", "unreadable vulnerabilities", "unreadable sbom", "source read error", "missing digest", "missing time", "complete"} {
		t.Run(scenario, func(t *testing.T) {
			root, p, s, v := fixture(t)
			switch scenario {
			case "complete":
			case "unreadable vulnerabilities":
				put(t, root, "cra/reports/vulnerabilities.json", "{")
			case "unreadable sbom":
				put(t, root, "cra/reports/sbom.cdx.json", "{")
			case "source read error":
				if err := os.Mkdir(filepath.Join(root, "composer.lock"), 0755); err != nil {
					t.Fatal(err)
				}
			case "missing digest", "missing time":
				if scenario == "missing digest" {
					s.InventoryDigest = ""
				} else {
					s.ScannedAt = time.Time{}
				}
				writeJSON(t, root, "inventory.json", s)
			case "offline", "offline release missing", "incomplete and changed":
				s.Complete, v.Complete = false, false
				s.Offline = scenario != "incomplete and changed"
				if scenario == "incomplete and changed" {
					put(t, root, "package.json", `{"name":"sample","version":"2.0.0"}`)
				}
				if scenario == "offline release missing" {
					s.Release = detect.String("../artifacts/maker's release.zip")
					s.InventoryDigest, _ = s.Inventory.Digest()
					v.InventoryDigest = s.InventoryDigest
				}
				saveEvidence(t, root, s, v)
			case "digest mismatch":
				s.Components = append(s.Components, inventory.Component{Name: "edited"})
				saveEvidence(t, root, s, v)
			case "missing metadata":
				s.ScanID = ""
				writeJSON(t, root, "inventory.json", s)
			case "unreadable inventory":
				put(t, root, "cra/reports/inventory.json", "{")
			case "release missing", "expired release missing", "source error with release", "source and release error":
				s.Release = detect.String("../artifacts/maker's release.zip")
				if scenario == "source error with release" {
					release := filepath.Join(root, "release")
					put(t, release, "package.json", `{"name":"sample","version":"1.0.0"}`)
					s.Release = detect.String("release")
				}
				if scenario == "expired release missing" {
					s.ScannedAt = frozenTime.Add(-8 * 24 * time.Hour)
					v.ScannedAt = s.ScannedAt
				}
				s.InventoryDigest, _ = s.Inventory.Digest()
				v.InventoryDigest = s.InventoryDigest
				saveEvidence(t, root, s, v)
				if strings.HasPrefix(scenario, "source") {
					put(t, root, "composer.lock", "{")
				}
			case "source error":
				put(t, root, "composer.lock", "{")
			case "missing inventory":
				os.Remove(filepath.Join(root, "cra/reports/inventory.json"))
			case "missing vulnerabilities":
				os.Remove(filepath.Join(root, "cra/reports/vulnerabilities.json"))
			case "missing sbom":
				os.Remove(filepath.Join(root, "cra/reports/sbom.cdx.json"))
			case "mixed vulnerabilities":
				v.ScanID = "other"
				writeJSON(t, root, "vulnerabilities.json", v)
			case "mixed sbom":
				s.ScanID = "other"
				saveEvidence(t, root, s, v)
			case "wrong sbom version":
				b, e := os.ReadFile(filepath.Join(root, "cra/reports/sbom.cdx.json"))
				if e != nil {
					t.Fatal(e)
				}
				put(t, root, "cra/reports/sbom.cdx.json", strings.ReplaceAll(string(b), `"version": "1.0.0"`, `"version": "2.0.0"`))
			case "changed inventory":
				put(t, root, "package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/thing":{"version":"1.0.0"}}}`)
			case "changed version":
				put(t, root, "package.json", `{"name":"sample","version":"2.0.0"}`)
			case "expired":
				s.ScannedAt = frozenTime.Add(-8 * 24 * time.Hour)
				v.ScannedAt = s.ScannedAt
				saveEvidence(t, root, s, v)
			case "incomplete":
				s.Complete = false
				v.Complete = false
				saveEvidence(t, root, s, v)
			case "coverage":
				s.CoverageGaps = []inventory.Gap{{Code: "unsupported-lockfile", Message: "Yarn lockfiles are not supported."}}
				s.InventoryDigest, _ = s.Inventory.Digest()
				v.InventoryDigest = s.InventoryDigest
				saveEvidence(t, root, s, v)
			}
			r := evaluate(t, root, p, false)
			wantState, detail := "incomplete", "incomplete (reports do not match)"
			wantCode := 11
			switch scenario {
			case "missing inventory", "missing metadata", "unreadable inventory", "missing digest", "missing time":
				wantState, detail = "missing", "missing"
			case "changed inventory", "changed version", "coverage":
				wantState, detail = "stale", "stale (components changed)"
			case "expired", "expired release missing":
				wantState, detail = "stale", "stale (older than seven days)"
			case "release missing", "source and release error":
				wantState, detail = "stale", "stale (release unavailable)"
			case "source error", "source error with release", "source read error":
				wantState, detail = "stale", "stale (inventory unavailable)"
			case "offline", "offline release missing":
				detail = "incomplete (lookups did not run)"
			case "incomplete", "incomplete and changed":
				detail = "incomplete (lookups failed)"
			case "complete":
				wantState, detail, wantCode = "complete", "complete", 0
			}
			if r.ExitCode != wantCode || r.ScanState != wantState || r.ScanDetail != detail || r.ScanComplete != (wantState == "complete") {
				t.Fatal(r.ExitCode, r.ScanState, r.ScanDetail, r.ScanIssues)
			}
			wantLabel := s.ScannedAt.Format("2006-01-02 15:04 UTC") + ", " + detail
			if wantState == "missing" {
				wantLabel = "missing"
			}
			if ScanLabel(r) != wantLabel {
				t.Fatal(ScanLabel(r), wantLabel)
			}
			if wantCode == 11 {
				if len(r.Next) == 0 || r.Next[0] != r.ScanRecovery || strings.Count(r.ScanRecovery, "fendkit scan") != 1 {
					t.Fatal(r.Next, r.ScanRecovery)
				}
				for _, a := range rankActions(r) {
					if a.text == "Run fendkit scan." {
						t.Fatal("duplicate SBOM recovery", a)
					}
				}
			} else if r.ScanRecovery != "" {
				t.Fatal(r.ScanRecovery)
			}
			for _, issue := range r.ScanIssues {
				if strings.Contains(issue, "fendkit scan") {
					t.Fatal(issue)
				}
			}
			if s.Release != nil {
				if !strings.Contains(r.ScanRecovery, "--release "+shellQuote(*s.Release)) {
					t.Fatal(r.ScanRecovery)
				}
				if scenario == "source error with release" {
					if strings.Contains(r.ScanRecovery, "Restore") || !strings.Contains(r.ScanRecovery, "composer.lock: invalid Composer lockfile") {
						t.Fatal(r.ScanRecovery)
					}
				} else if !strings.Contains(r.ScanRecovery, "Restore the recorded release "+*s.Release) {
					t.Fatal(r.ScanRecovery)
				}
			}
			if strings.HasPrefix(scenario, "source") && scenario != "source read error" && !strings.Contains(r.ScanRecovery, "composer.lock: invalid Composer lockfile") {
				t.Fatal(r.ScanRecovery)
			}
			expected := map[string]string{
				"missing inventory":    "No usable saved scan is available. Run fendkit scan.",
				"unreadable inventory": "No usable saved scan is available. Run fendkit scan.",
				"missing metadata":     "No usable saved scan is available. Run fendkit scan.",
				"offline":              "Vulnerability lookups did not run. Run fendkit scan with network access.",
				"incomplete":           "Vulnerability lookups failed: the saved scan did not finish. Run fendkit scan again, or fendkit doctor to check the connection.",
				"missing sbom":         "Saved reports are missing or do not belong to one scan. Run fendkit scan.",
				"digest mismatch":      "Saved reports are missing or do not belong to one scan. Run fendkit scan.",
				"changed inventory":    "Your components or product version changed since the last scan. Run fendkit scan.",
				"expired":              "The last scan is older than seven days. Run fendkit scan.",
			}
			if want, ok := expected[scenario]; ok && r.ScanRecovery != want {
				t.Fatal(r.ScanRecovery, want)
			}
			diagnostics := map[string]string{"missing inventory": "is missing: cra/reports/inventory.json", "unreadable inventory": "is unreadable: cra/reports/inventory.json", "missing metadata": "missing metadata: scan_id", "missing digest": "missing metadata: inventory_digest", "missing time": "missing metadata: scanned_at", "source read error": "composer.lock: cannot read; check permissions"}
			if want, ok := diagnostics[scenario]; ok && !strings.Contains(strings.Join(r.ScanIssues, " "), want) {
				t.Fatal(r.ScanIssues, want)
			}
			if scenario == "offline release missing" && !strings.Contains(r.ScanRecovery, "with network access") {
				t.Fatal(r.ScanRecovery)
			}
			if scenario == "incomplete and changed" && !strings.Contains(strings.Join(r.ScanIssues, " "), "Product version changed") {
				t.Fatal(r.ScanIssues)
			}
			if scenario == "missing sbom" && r.Items[4].State != Missing {
				t.Fatal("absent SBOM must be missing", r.Items[4])
			}
			if scenario != "complete" && r.Items[5].State != Review {
				t.Fatal(r.Items[5])
			}
		})
	}
	for _, state := range []string{"untriaged", "affected", "under_investigation", "fixed", "not_affected"} {
		for _, shipped := range []bool{true, false} {
			t.Run(fmt.Sprint(state, shipped), func(t *testing.T) {
				root, p, s, v := fixture(t)
				f := finding("package", "high", shipped)
				f.KnownExploited = true
				v.Findings = []vulns.Finding{f}
				if state != "untriaged" {
					p.Triage = []profile.Triage{{Advisory: &f.IDs[0], Component: &f.Component.PURL, Status: &state, Reason: detect.String("Recorded reason")}}
				}
				saveEvidence(t, root, s, v)
				r := evaluate(t, root, p, false)
				want := 0
				if shipped && state != "fixed" && state != "not_affected" {
					want = 10
				}
				if r.ExitCode != want {
					t.Fatal(r.ExitCode, want)
				}
				v.Complete = false
				writeJSON(t, root, "vulnerabilities.json", v)
				r = evaluate(t, root, p, false)
				if want == 0 {
					want = 11
				}
				if r.ExitCode != want {
					t.Fatal("precedence", r.ExitCode, want)
				}
			})
		}
	}
}
func frozenReport(t *testing.T) Result {
	root, p, _, _ := fixture(t)
	r := evaluate(t, root, p, false)
	r.Product.Name = detect.String("Acme <Booking> & Forms")
	r.Components = nil
	r.Findings = nil
	for _, spec := range []struct {
		name, label string
		count       int
	}{{"guzzlehttp/guzzle", "high", 13}, {"jquery-validation", "high", 4}, {"moment", "high", 2}, {"guzzlehttp/psr7", "moderate", 6}, {"select2", "moderate", 1}, {"development-only", "critical", 20}} {
		for i := 0; i < spec.count; i++ {
			f := finding(spec.name, spec.label, spec.name != "development-only")
			f.IDs = []string{fmt.Sprintf("GHSA-%s-%02d", spec.name, i)}
			f.Advisories[0].ID = f.IDs[0]
			r.Findings = append(r.Findings, f)
			if i == 0 {
				r.Components = append(r.Components, f.Component)
			}
		}
	}
	for i := range r.Items {
		if i >= 2 && i != 4 && i != 5 && i != 12 {
			r.Items[i].State = Review
			r.Items[i].Explanation = "Draft document needs your review."
		}
	}
	for i := range r.Documents {
		r.Documents[i].Status = "draft"
		r.Documents[i].State = Review
		r.Documents[i].ReviewedBy = ""
		r.Documents[i].ReviewedOn = ""
	}
	r.Components = append(r.Components, inventory.Component{Name: "Local <adapter> & helpers", Version: detect.String("1.0.0"), PURL: "pkg:generic/local-adapter@1.0.0"})
	r.Next = nil
	for _, a := range rankActions(r) {
		if len(r.Next) == 5 {
			break
		}
		r.Next = append(r.Next, a.text)
	}
	return r
}
func TestRankingAndReports(t *testing.T) {
	r := frozenReport(t)
	for i, name := range []string{"guzzlehttp/guzzle", "jQuery Validation", "moment.js", "guzzlehttp/psr7", "Select2"} {
		if !strings.Contains(r.Next[i], name) || !strings.Contains(r.Next[i], "assets/js/vendor/") {
			t.Fatal(r.Next)
		}
	}
	var terminal, markdown, page bytes.Buffer
	Terminal(&terminal, r, 80)
	Markdown(&markdown, r)
	if e := HTML(&page, r); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(terminal.String(), "Update guzzlehttp/psr7") || !strings.Contains(terminal.String(), "Update moment.js") {
		t.Fatal(terminal.String())
	}
	for _, section := range []string{"Next steps", "Checklist", "Shipped and possibly shipped components", "Non-shipped findings", "Documents", "Coverage gaps"} {
		for _, s := range []string{markdown.String(), page.String()} {
			if !strings.Contains(s, section) {
				t.Fatal(section)
			}
		}
	}
	if strings.Contains(page.String(), "<b>markup</b>") || !strings.Contains(page.String(), "&lt;b&gt;markup&lt;/b&gt;") || strings.Contains(page.String(), "<Booking>") || strings.Contains(page.String(), "<adapter>") || !strings.Contains(page.String(), "&lt;adapter&gt;") {
		t.Fatal("HTML not escaped")
	}
	for _, s := range []string{terminal.String(), markdown.String(), page.String()} {
		for _, banned := range []string{"compliant product", "cra compliant", "certified", "guarantee", "ensures compliance", "cra-ready"} {
			if strings.Contains(strings.ToLower(s), banned) {
				t.Fatal(banned)
			}
		}
		if !strings.Contains(html.UnescapeString(s), Legal) {
			t.Fatal("missing legal wording")
		}
	}
	for _, s := range []string{markdown.String(), page.String()} {
		if !strings.Contains(html.UnescapeString(s), Scope) {
			t.Fatal("missing report scope wording")
		}
	}
	if strings.Contains(page.String(), "<script") || strings.Contains(page.String(), "<link") || strings.Contains(page.String(), "<img") {
		t.Fatal("external resources or scripts")
	}
	root := t.TempDir()
	if e := Write(root, r); e != nil {
		t.Fatal(e)
	}
	if path := os.Getenv("FENDKIT_STATUS_FIXTURE"); path != "" {
		if e := Write(path, r); e != nil {
			t.Fatal(e)
		}
	}
}
func TestComponentNameTieAndUnknownRoleOrder(t *testing.T) {
	r := Result{Findings: []vulns.Finding{finding("zebra", "high", true), finding("alpha", "high", true)}, Items: []Item{{Name: "Role", State: Review, Action: "Decide role"}, {Name: "Classification", State: Review, Action: "Decide class"}}}
	actions := rankActions(r)
	if !strings.Contains(actions[0].text, "alpha") || !strings.Contains(actions[1].text, "zebra") || actions[2].text != "Decide role" {
		t.Fatal(actions)
	}
}

func TestCoverageGapsWithCompletedLookups(t *testing.T) {
	for _, scenario := range []string{"unsupported lockfile", "unresolved runtime", "unknown version", "uncovered fork", "modified copy"} {
		t.Run(scenario, func(t *testing.T) {
			root, p, _, _ := fixture(t)
			switch scenario {
			case "unsupported lockfile":
				put(t, root, "yarn.lock", "# yarn lockfile v1\n")
			case "unresolved runtime":
				put(t, root, "package.json", `{"name":"sample","version":"1.0.0","dependencies":{"some-package":"^1.0.0"}}`)
			case "unknown version":
				p.Components = []profile.Component{{Name: detect.String("unknown-package"), Ecosystem: detect.String("npm")}}
			case "uncovered fork":
				p.Components = []profile.Component{{Name: detect.String("custom-fork"), Version: detect.String("1.0.0"), Ecosystem: detect.String("other")}}
			case "modified copy":
				put(t, root, "assets/select2.js", "/*! Select2 3.5.4-tribe */")
			}
			product, e := detect.Detect(root)
			if e != nil {
				t.Fatal(e)
			}
			inv, e := inventory.BuildWithOptions(root, product, inventory.Options{Profile: p})
			if e != nil {
				t.Fatal(e)
			}
			digest, _ := inv.Digest()
			s := Scan{ScanID: "gap-scan", ScannedAt: frozenTime, Complete: true, ProductVersion: inv.Product.Version, InventoryDigest: digest, Inventory: inv}
			v := vulns.Report{ScanID: s.ScanID, ScannedAt: s.ScannedAt, Complete: true, ProductVersion: s.ProductVersion, InventoryDigest: digest, CoverageGaps: inv.CoverageGaps}
			saveEvidence(t, root, s, v)
			r := evaluate(t, root, p, false)
			if r.ExitCode != 0 || !r.ScanComplete || r.Items[5].State != Review || len(r.CoverageGaps) == 0 {
				t.Fatalf("%s: %+v", scenario, r)
			}
		})
	}
}
func TestStrictMissingActionsComeFirst(t *testing.T) {
	root, p, _, _ := fixture(t)
	os.Remove(filepath.Join(root, "cra/user-information.md"))
	r := evaluate(t, root, p, true)
	if r.ExitCode != 10 || !strings.Contains(r.Next[0], "user-information.md") {
		t.Fatal(r.ExitCode, r.Next)
	}
}

func TestPossiblyShippedPolicyAndResolvedReasons(t *testing.T) {
	root, p, s, v := fixture(t)
	f := finding("dependency", "high", true)
	f.Component.Shipped = nil
	f.KnownExploited = true
	v.Findings = []vulns.Finding{f}
	saveEvidence(t, root, s, v)
	r := evaluate(t, root, p, false)
	if r.ExitCode != 10 || !strings.HasPrefix(r.Next[0], "Known exploited:") {
		t.Fatal(r.ExitCode, r.Next)
	}
	p.Triage = []profile.Triage{{Advisory: &f.IDs[0], Component: &f.Component.PURL, Status: detect.String("not_affected"), Reason: detect.String("The vulnerable path is not called.")}}
	r = evaluate(t, root, p, false)
	if r.ExitCode != 0 || r.Items[5].State != Evidenced {
		t.Fatal(r.Items[5])
	}
	var page, md bytes.Buffer
	if e := HTML(&page, r); e != nil {
		t.Fatal(e)
	}
	Markdown(&md, r)
	for _, s := range []string{page.String(), md.String()} {
		if !strings.Contains(s, "The vulnerable path is not called.") || !strings.Contains(html.UnescapeString(s), "not_affected") {
			t.Fatal("resolved decision lost")
		}
	}
}
func TestSourceSeverityOrdering(t *testing.T) {
	r := Result{Findings: []vulns.Finding{finding("unrated", "not rated (CVSS:3.1/...)", true), finding("low", "low", true), finding("medium", "medium", true), finding("moderate", "moderate", true), finding("high", "HIGH", true), finding("critical", "CRITICAL", true)}}
	actions := rankActions(r)
	for i, name := range []string{"critical", "high", "medium", "moderate", "low", "unrated"} {
		if !strings.Contains(actions[i].text, "Update "+name+" ") {
			t.Fatal(actions)
		}
	}
}

func TestIncompleteScanExplanation(t *testing.T) {
	for _, failure := range []string{"Offline scan: vulnerability lookups have not run", "CISA KEV: HTTP 503; run fendkit scan again", "OSV GHSA-example: HTTP 503; run fendkit scan again."} {
		t.Run(failure, func(t *testing.T) {
			root, p, s, v := fixture(t)
			s.Complete, v.Complete = false, false
			s.Offline = strings.HasPrefix(failure, "Offline")
			s.IncompleteReasons = []string{" ", failure}
			v.Reason = []string{failure}
			saveEvidence(t, root, s, v)
			beforeInv := readText(t, root, "cra/reports/inventory.json")
			beforeVuln := readText(t, root, "cra/reports/vulnerabilities.json")
			r := evaluate(t, root, p, false)
			if r.ExitCode != 11 || r.ScanState != "incomplete" || len(r.ScanIssues) != 1 {
				t.Fatal(r)
			}
			clean := scanReason(failure)
			if !strings.Contains(r.ScanIssues[0], clean) || strings.Contains(r.ScanIssues[0], "run fendkit scan") || !strings.Contains(r.Items[5].Explanation, clean) {
				t.Fatal(r.ScanIssues, r.Items[5])
			}
			if strings.Count(r.ScanRecovery, "fendkit scan") != 1 || strings.Contains(r.ScanRecovery, "; run fendkit scan again") {
				t.Fatal(r.ScanRecovery)
			}
			if s.Offline {
				if !strings.Contains(r.ScanRecovery, "with network access") {
					t.Fatal(r.ScanRecovery)
				}
			} else if !strings.Contains(r.ScanRecovery, "Vulnerability lookups failed: "+clean+". Run fendkit scan again, or fendkit doctor") {
				t.Fatal(r.ScanRecovery)
			}
			var terminal bytes.Buffer
			Terminal(&terminal, r, 80)
			if strings.Contains(terminal.String(), "; run fendkit scan again") {
				t.Fatal(terminal.String())
			}
			if beforeInv != readText(t, root, "cra/reports/inventory.json") || beforeVuln != readText(t, root, "cra/reports/vulnerabilities.json") {
				t.Fatal("presentation changed saved evidence")
			}
			s.IncompleteReasons = []string{" "}
			saveEvidence(t, root, s, v)
			fallback := evaluate(t, root, p, false)
			if fallback.ScanRecovery != r.ScanRecovery {
				t.Fatal("vulnerability reason fallback", fallback.ScanRecovery, r.ScanRecovery)
			}

		})
	}
}
func TestCurrentSBOMDoesNotAskForImmediateRescan(t *testing.T) {
	root, p, _, _ := fixture(t)
	r := evaluate(t, root, p, false)
	var terminal bytes.Buffer
	Terminal(&terminal, r, 80)
	if strings.Contains(terminal.String(), "The SBOM belongs") || strings.Contains(terminal.String(), "Run fendkit scan.") {
		t.Fatal(terminal.String())
	}
	if r.Items[4].State != Evidenced || r.Items[4].Action == "Run fendkit scan." {
		t.Fatal(r.Items[4])
	}
}
func TestDeclarationReminderAndStewardNote(t *testing.T) {
	root, p, _, _ := fixture(t)
	p.Role.Answer = "open-source-steward"
	r := evaluate(t, root, p, false)
	if !strings.Contains(r.Items[10].Explanation, "Draft, not signed; sign before placing on the market from December 11, 2027.") {
		t.Fatal(r.Items[10])
	}
	var terminal, markdown, page bytes.Buffer
	Terminal(&terminal, r, 80)
	Markdown(&markdown, r)
	if e := HTML(&page, r); e != nil {
		t.Fatal(e)
	}
	for _, text := range []string{markdown.String(), page.String()} {
		if !strings.Contains(text, "does not assess steward obligations under Art. 24.") || !strings.Contains(text, "sign before placing on the market from December 11, 2027.") {
			t.Fatal("missing maker responsibility wording", text)
		}
	}
	if strings.Contains(terminal.String(), "Art. 24") || strings.Contains(terminal.String(), "sign before placing") {
		t.Fatal("report details leaked into terminal output", terminal.String())
	}
}

func TestCompactTerminalStatus(t *testing.T) {
	root, p, s, v := fixture(t)
	p.Role.Answer = "open-source-steward"
	p.Classification.Answer = "important-class-i"
	for _, file := range docs.Files {
		put(t, root, file, "Draft: [[review]]")
	}
	s.Complete, v.Complete = false, false
	s.IncompleteReasons = []string{"Offline scan: vulnerability lookups have not run"}
	v.Reason = s.IncompleteReasons
	saveEvidence(t, root, s, v)
	r := evaluate(t, root, p, false)
	for _, width := range []int{60, 80, 100, 240} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			var terminal bytes.Buffer
			Terminal(&terminal, r, width)
			text := terminal.String()
			for _, detail := range []string{Scope, Assessment, "sign before placing", "fill remaining placeholders", "Art. 24", "Coverage gap:"} {
				if strings.Contains(text, detail) {
					t.Fatalf("report detail %q in terminal: %s", detail, text)
				}
			}
			for _, want := range []string{"Fendkit  ", "\nNext\n", r.Next[0], r.Next[1], r.Next[2], r.Items[4].Explanation, r.ScanIssues[0], "\nFull status: cra/reports/status.html\n" + Legal + "\n"} {
				if !strings.Contains(text, want) {
					t.Fatalf("missing %q in terminal: %s", want, text)
				}
			}
			if strings.Contains(text, "  4.") {
				t.Fatal("terminal should highlight only three next actions")
			}
			_, rows, ok := strings.Cut(text, "\nStatus\n")
			if !ok {
				t.Fatal("missing status block")
			}
			rows, _, _ = strings.Cut(rows, "\n\n")
			wrapped := false
			for _, line := range strings.Split(rows, "\n") {
				if len(line) > width {
					t.Fatalf("status line exceeds width %d: %q", width, line)
				}
				if strings.HasPrefix(line, "   ") {
					wrapped = true
					if !strings.HasPrefix(line, strings.Repeat(" ", 17)) || line[17] == ' ' {
						t.Fatalf("continuation must align with item names: %q", line)
					}
				}
			}
			if wrapped != (width < 240) {
				t.Fatalf("unexpected wrapping at width %d: %s", width, rows)
			}
			normalized := strings.Join(strings.Fields(rows), " ")
			if !strings.Contains(normalized, "Security contact, Disclosure policy, SBOM, Known vulnerabilities, Support period, User information, Risk assessment, Technical documentation, EU declaration of conformity, Incident readiness") || !strings.Contains(normalized, "Open incidents (none)") {
				t.Fatal("wrapped output lost status items", rows)
			}
		})
	}
	if got := OutputWidth(&bytes.Buffer{}); got != 80 {
		t.Fatalf("redirected output width = %d, want 80", got)
	}
	var markdown, page bytes.Buffer
	Markdown(&markdown, r)
	if err := HTML(&page, r); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{markdown.String(), page.String()} {
		for _, detail := range []string{Scope, Assessment, "sign before placing", "Art. 24"} {
			if !strings.Contains(html.UnescapeString(text), detail) {
				t.Fatalf("report lost %q", detail)
			}
		}
	}
}
func TestStatusLegalWordingAcrossEvidenceAndRoles(t *testing.T) {
	for _, scenario := range []string{"manufacturer", "not-in-scope", "unknown", "open-source-steward", "important-class-i", "important-class-ii", "critical", "missing scan", "incomplete scan", "known exploited", "draft documents"} {
		t.Run(scenario, func(t *testing.T) {
			root, p, s, v := fixture(t)
			switch scenario {
			case "manufacturer", "not-in-scope", "unknown", "open-source-steward":
				p.Role.Answer = scenario
			case "important-class-i", "important-class-ii", "critical":
				p.Classification.Answer = scenario
			case "missing scan":
				os.Remove(filepath.Join(root, "cra/reports/inventory.json"))
			case "incomplete scan":
				s.Complete = false
				v.Complete = false
				s.IncompleteReasons = []string{"Offline scan: vulnerability lookups have not run"}
				v.Reason = s.IncompleteReasons
				saveEvidence(t, root, s, v)
			case "known exploited":
				f := finding("dependency", "high", true)
				f.KnownExploited = true
				v.Findings = []vulns.Finding{f}
				saveEvidence(t, root, s, v)
			case "draft documents":
				for _, file := range docs.Files {
					put(t, root, file, "Draft: [[review]]")
				}
			}
			r := evaluate(t, root, p, false)
			var terminal, markdown, page bytes.Buffer
			Terminal(&terminal, r, 80)
			Markdown(&markdown, r)
			if e := HTML(&page, r); e != nil {
				t.Fatal(e)
			}
			if e := Write(root, r); e != nil {
				t.Fatal(e)
			}
			if e := docs.WriteIndex(root, p, frozenTime, r.Next, ScanLabel(r), false); e != nil {
				t.Fatal(e)
			}
			encoded, e := json.Marshal(r)
			if e != nil {
				t.Fatal(e)
			}
			for _, text := range []string{terminal.String(), markdown.String(), page.String(), string(encoded), readText(t, root, "cra/README.md"), readText(t, root, "cra/reports/status.md"), readText(t, root, "cra/reports/status.html")} {
				for _, bad := range []string{"compliant product", "cra compliant", "certified", "guarantee", "ensures compliance", "cra-ready"} {
					if strings.Contains(strings.ToLower(html.UnescapeString(text)), bad) {
						t.Fatalf("forbidden wording %q", bad)
					}
				}
			}
		})
	}
}
func readText(t *testing.T, root, file string) string {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(root, file))
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}

func TestSecurityContactReviewExplanations(t *testing.T) {
	for _, scenario := range []struct {
		name, securityStatus, textStatus, want string
		state                                  State
	}{
		{"different review dates", "reviewed", "reviewed", "SECURITY.md: Review recorded by Ana on 2026-10-20. cra/security.txt: Review recorded by Ana on 2026-10-21. Publication cannot be checked locally.", Evidenced},
		{"security policy reviewed", "reviewed", "draft", "Review cra/security.txt, fill remaining placeholders and record the reviewer and review date. SECURITY.md: Review recorded by Ana on 2026-10-20. Publication cannot be checked locally.", Review},
		{"security text reviewed", "draft", "reviewed", "Review SECURITY.md, fill remaining placeholders and record the reviewer and review date. cra/security.txt: Review recorded by Ana on 2026-10-21. Publication cannot be checked locally.", Review},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			root, p, _, _ := fixture(t)
			put(t, root, "SECURITY.md", "---\nstatus: "+scenario.securityStatus+"\nreviewed_by: Ana\nreviewed_on: 2026-10-20\n---\nContact: security@example.com\n")
			put(t, root, "cra/security.txt", "# status: "+scenario.textStatus+"\n# reviewed_by: Ana\n# reviewed_on: 2026-10-21\nContact: mailto:security@example.com\nExpires: 2027-10-19T12:00:00Z\n")
			r := evaluate(t, root, p, false)
			if row := r.Items[2]; row.State != scenario.state || row.Explanation != scenario.want {
				t.Fatalf("Security contact: %+v; want %s / %s", row, scenario.state, scenario.want)
			}
			var markdown, page bytes.Buffer
			Markdown(&markdown, r)
			if err := HTML(&page, r); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			for _, output := range []string{markdown.String(), page.String(), string(encoded)} {
				if !strings.Contains(html.UnescapeString(output), scenario.want) {
					t.Fatal("review explanation differs across outputs", output)
				}
			}
		})
	}
}
