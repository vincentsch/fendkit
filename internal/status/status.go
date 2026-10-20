package status

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/vincentsch/conformline/internal/detect"
	"github.com/vincentsch/conformline/internal/docs"
	"github.com/vincentsch/conformline/internal/inventory"
	"github.com/vincentsch/conformline/internal/profile"
	"github.com/vincentsch/conformline/internal/vulns"
	"gopkg.in/yaml.v3"
)

type State string

const (
	Evidenced State = "evidenced"
	Review    State = "needs review"
	Missing   State = "missing"
	NA        State = "not applicable"
)
const Assessment = "Your classification may require a conformity assessment by a third party. Conformline does not prepare or assess that procedure."
const AssessmentURL = "https://digital-strategy.ec.europa.eu/en/policies/cra-conformity-assessment"
const Legal = "Not legal advice. Conformline helps you prepare; the decisions and the signature are yours."
const Scope = "Conformline only checks third-party components. It does not check the maker's own code for vulnerabilities. A scan without findings does not prove the absence of vulnerabilities."

type Item struct {
	Name        string `json:"name"`
	State       State  `json:"state"`
	Explanation string `json:"explanation"`
	Action      string `json:"action"`
}
type Document struct {
	Path        string `json:"path"`
	Status      string `json:"status"`
	ReviewedBy  string `json:"reviewed_by"`
	ReviewedOn  string `json:"reviewed_on"`
	State       State  `json:"state"`
	Explanation string `json:"explanation"`
}
type Scan struct {
	ScanID            string    `json:"scan_id"`
	ScannedAt         time.Time `json:"scanned_at"`
	ProductVersion    *string   `json:"product_version"`
	InventoryDigest   string    `json:"inventory_digest"`
	Complete          bool      `json:"complete"`
	IncompleteReasons []string  `json:"incomplete_reasons"`
	inventory.Inventory
}
type Result struct {
	LegalNotice  string                `json:"legal_notice"`
	Strict       bool                  `json:"strict"`
	Product      detect.Product        `json:"product"`
	ScannedAt    time.Time             `json:"scanned_at"`
	ScanComplete bool                  `json:"scan_complete"`
	ScanIssues   []string              `json:"scan_issues"`
	Items        []Item                `json:"items"`
	Next         []string              `json:"next_actions"`
	Components   []inventory.Component `json:"components"`
	Findings     []vulns.Finding       `json:"findings"`
	CoverageGaps []inventory.Gap       `json:"coverage_gaps"`
	Documents    []Document            `json:"documents"`
	Notes        []string              `json:"notes"`
	ExitCode     int                   `json:"exit_code"`
	DryRun       bool                  `json:"dry_run"`
}

func Value(p *string) string {
	if p == nil {
		return "unknown"
	}
	return *p
}
func readJSON(root, file string, out any) bool {
	b, e := os.ReadFile(filepath.Join(root, "cra/reports", file))
	return e == nil && json.Unmarshal(b, out) == nil
}
func same(a, b *string) bool     { return Value(a) == Value(b) }
func reviewedDate(s string) bool { _, e := time.Parse("2006-01-02", s); return e == nil }
func InspectDocument(root, file string, now time.Time) Document {
	d := Document{Path: file, Status: "missing", State: Missing, Explanation: "The file is missing."}
	b, e := os.ReadFile(filepath.Join(root, file))
	if e != nil {
		if !os.IsNotExist(e) {
			d.Status = "unreadable"
			d.State = Review
			d.Explanation = "The file cannot be read; check its permissions."
		}
		return d
	}
	text := strings.ReplaceAll(string(b), "\r\n", "\n")
	var meta struct {
		Status string `yaml:"status"`
		By     string `yaml:"reviewed_by"`
		On     string `yaml:"reviewed_on"`
	}
	metadata := ""
	if strings.HasSuffix(file, "security.txt") {
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "# status:") || strings.HasPrefix(line, "# reviewed_by:") || strings.HasPrefix(line, "# reviewed_on:") {
				metadata += strings.TrimPrefix(line, "# ") + "\n"
			}
		}
	} else if strings.HasPrefix(text, "---\n") {
		if end := strings.Index(text[4:], "\n---"); end >= 0 {
			metadata = text[4 : 4+end]
		}
	}
	_ = yaml.Unmarshal([]byte(metadata), &meta)
	d.Status = meta.Status
	if d.Status == "" {
		d.Status = "unmarked"
	}
	d.ReviewedBy = meta.By
	d.ReviewedOn = meta.On
	d.State = Review
	d.Explanation = "Review the draft, fill remaining placeholders and record the reviewer and review date."
	if meta.Status == "reviewed" && strings.TrimSpace(meta.By) != "" && reviewedDate(meta.On) && !strings.Contains(text, "[[") {
		d.State = Evidenced
		d.Explanation = "Review recorded by " + meta.By + " on " + meta.On + "."
	}
	if strings.HasSuffix(file, "security.txt") {
		contact, expiry := false, false
		for _, line := range strings.Split(text, "\n") {
			if v, ok := strings.CutPrefix(line, "Contact: "); ok {
				u, e := url.Parse(strings.TrimSpace(v))
				if e == nil {
					if u.Scheme == "https" && u.Host != "" && u.User == nil {
						contact = true
					}
					if u.Scheme == "mailto" {
						_, e := mail.ParseAddress(u.Opaque)
						contact = contact || e == nil
					}
				}
			}
			if v, ok := strings.CutPrefix(line, "Expires: "); ok {
				t, e := time.Parse(time.RFC3339, strings.TrimSpace(v))
				expiry = e == nil && t.After(now)
			}
		}
		if !contact || !expiry {
			d.State = Review
			d.Explanation = "security.txt needs a valid contact and a future Expires date."
		}
	}
	if file == "SECURITY.md" && !strings.Contains(text, "mailto:") && !strings.Contains(text, "https://") && !strings.Contains(text, "@") {
		d.State = Review
		d.Explanation = "SECURITY.md needs a vulnerability reporting contact."
	}
	return d
}

func Evaluate(root string, p *profile.Profile, now time.Time, strict bool) (Result, error) {
	product, e := detect.Detect(root)
	if e != nil {
		return Result{}, e
	}
	if p.Product.Version != nil {
		product.Version = p.Product.Version
		if product.DetectedVersion != nil && !same(product.Version, product.DetectedVersion) {
			product.Notes = append(product.Notes, "product.version overrides the detected version; review both versions in inventory.json")
		}
	}
	if p.Product.Name != nil {
		product.Name = p.Product.Name
	}
	if p.Product.Type != nil {
		product.Type = *p.Product.Type
	}
	r := Result{LegalNotice: Legal, Strict: strict, Product: product, Next: []string{}, ScanIssues: []string{}, Notes: []string{Scope}, Items: []Item{}, Documents: []Document{}}
	var saved Scan
	invOK := readJSON(root, "inventory.json", &saved)
	var vr vulns.Report
	vulnOK := readJSON(root, "vulnerabilities.json", &vr)
	issue := func(s string) { r.ScanIssues = append(r.ScanIssues, sentence(s)+" Run conformline scan.") }
	if !invOK || saved.ScanID == "" || saved.InventoryDigest == "" || saved.ScannedAt.IsZero() {
		issue("Inventory scan evidence is missing or unreadable.")
	} else {
		r.ScannedAt = saved.ScannedAt
		r.Components = saved.Components
		r.CoverageGaps = saved.CoverageGaps
		digest, _ := saved.Inventory.Digest()
		if digest != saved.InventoryDigest {
			issue("Saved inventory content differs from its scan digest.")
		}
		current, err := inventory.BuildWithOptions(root, product, inventory.Options{Release: saved.Release, ReplayRelease: true, Profile: p})
		if err != nil {
			if saved.Release != nil {
				issue("The recorded release " + *saved.Release + " is missing, unreadable or differs from the product; restore that release and review the product version.")
			} else {
				issue("Local inventory cannot be rebuilt; check source files and permissions.")
			}
		} else {
			d, _ := current.Digest()
			r.Product = current.Product
			if d != saved.InventoryDigest {
				issue("Inventory content changed since the saved scan.")
			}
		}
		if !same(saved.ProductVersion, r.Product.Version) {
			issue("Product version changed since the saved scan.")
		}
		if now.Sub(saved.ScannedAt) > 7*24*time.Hour {
			issue("The scan is older than seven days.")
		}
	}
	if !vulnOK || vr.ScanID == "" {
		issue("Vulnerability scan evidence is missing or unreadable.")
	} else {
		// Keep known policy failures visible even when scan evidence is mixed.
		vulns.Apply(&vr, p)
		r.Findings = vr.Findings
		for _, f := range r.Findings {
			if !slices.ContainsFunc(r.Components, func(c inventory.Component) bool { return c.PURL == f.Component.PURL }) {
				r.Components = append(r.Components, f.Component)
			}
		}
		r.CoverageGaps = append(r.CoverageGaps, vr.CoverageGaps...)
		if !invOK || vr.ScanID != saved.ScanID || vr.InventoryDigest != saved.InventoryDigest || !vr.ScannedAt.Equal(saved.ScannedAt) || !same(vr.ProductVersion, saved.ProductVersion) || vr.Complete != saved.Complete {
			issue("Inventory and vulnerability evidence do not belong to the same scan.")
		}
	}
	if invOK && !saved.Complete || vulnOK && !vr.Complete {
		reasons := []string{}
		for _, reason := range append(append([]string{}, saved.IncompleteReasons...), vr.Reason...) {
			reason = sentence(reason)
			if reason != "" && !slices.Contains(reasons, reason) {
				reasons = append(reasons, reason)
			}
		}
		issue("The last scan is incomplete. " + strings.Join(reasons, " "))
	}
	var bom struct {
		Metadata struct {
			Component  struct{ Version string }
			Properties []struct{ Name, Value string }
		}
	}
	bomOK := readJSON(root, "sbom.cdx.json", &bom)
	props := map[string]string{}
	for _, v := range bom.Metadata.Properties {
		props[v.Name] = v.Value
	}
	if !bomOK {
		issue("SBOM scan evidence is missing or unreadable.")
	} else if props["conformline:scan_id"] != saved.ScanID || props["conformline:inventory_digest"] != saved.InventoryDigest || props["conformline:scanned_at"] != saved.ScannedAt.Format(time.RFC3339Nano) || props["conformline:complete"] != fmt.Sprint(saved.Complete) || (saved.ProductVersion == nil && bom.Metadata.Component.Version != "" || saved.ProductVersion != nil && bom.Metadata.Component.Version != *saved.ProductVersion) {
		issue("SBOM evidence does not belong to the saved scan.")
	}
	r.ScanComplete = len(r.ScanIssues) == 0
	add := func(name string, state State, explanation, action string) {
		r.Items = append(r.Items, Item{name, state, explanation, action})
	}
	decision := func(name, answer, field string) {
		if answer == "unknown" || answer == "" {
			add(name, Review, "This needs your decision.", "Decide "+field+" in cra.yml.")
		} else {
			add(name, Evidenced, "Your recorded decision: "+answer+".", "Review this decision when the product changes.")
		}
	}
	decision("Role", p.Role.Answer, "role.answer")
	if p.Role.Answer == "open-source-steward" {
		r.Notes = append(r.Notes, "Conformline v0.1 follows manufacturer preparation steps. It does not assess steward obligations under Art. 24.")
	}
	decision("Classification", p.Classification.Answer, "classification.answer")
	assessment := p.Classification.Answer == "important-class-i" || p.Classification.Answer == "important-class-ii" || p.Classification.Answer == "critical"
	if assessment {
		r.Items[1].Explanation += " " + Assessment + " " + AssessmentURL
	}
	documentMap := map[string]Document{}
	for _, file := range docs.Files {
		d := InspectDocument(root, file, now)
		if p.Role.Answer == "not-in-scope" {
			d.State = NA
			d.Status = string(NA)
			d.Explanation = "Manufacturer documents are skipped for your recorded not-in-scope role."
		}
		r.Documents = append(r.Documents, d)
		documentMap[file] = d
	}
	sec, txt := documentMap["SECURITY.md"], documentMap["cra/security.txt"]
	securityState := Evidenced
	if sec.State != Evidenced || txt.State != Evidenced {
		securityState = Review
	}
	if sec.State == Missing || txt.State == Missing {
		securityState = Missing
	}
	add("Security contact", securityState, sec.Explanation+" "+txt.Explanation+" Publication cannot be checked locally.", "Review SECURITY.md and cra/security.txt; publish the policy and /.well-known/security.txt over HTTPS.")
	docItem := func(name, file string) {
		d := documentMap[file]
		add(name, d.State, d.Explanation, "Review "+file+" and set status: reviewed, reviewed_by and reviewed_on.")
	}
	docItem("Disclosure policy", "cra/disclosure-policy.md")
	sbomState := Evidenced
	sbomWhy := "The SBOM belongs to the current scan and product version."
	if !bomOK {
		sbomState = Missing
		sbomWhy = "The SBOM is absent or unreadable."
	} else if !r.ScanComplete || r.Product.Version == nil || bom.Metadata.Component.Version != Value(r.Product.Version) {
		sbomState = Review
		sbomWhy = "Review the SBOM: scan evidence or product version is incomplete or stale."
	}
	productAction := "Run conformline scan."
	if sbomState == Evidenced {
		productAction = "Scan again when the product or its components change, or after seven days."
	}
	if r.Product.Version == nil {
		sbomState = Review
		if !bomOK {
			sbomState = Missing
		}
		sbomWhy += " The product version is unknown."
		productAction = "Set product.version in cra.yml, then run conformline scan."
	}
	if p.Product.Version != nil && product.DetectedVersion != nil && !same(p.Product.Version, product.DetectedVersion) {
		sbomState = Review
		sbomWhy += fmt.Sprintf(" Configured product.version %s differs from detected version %s.", *p.Product.Version, *product.DetectedVersion)
		productAction = "Review product.version in cra.yml and the detected version, then run conformline scan."
	}
	for _, note := range r.Product.Notes {
		if strings.Contains(note, "Stable tag") {
			sbomState = Review
			sbomWhy += " " + note
			productAction = "Review and align readme.txt Stable tag and the WordPress header, then run conformline scan."
		}
	}
	add("SBOM", sbomState, sbomWhy, productAction)
	for _, c := range r.Components {
		if c.Modified {
			r.CoverageGaps = append(r.CoverageGaps, inventory.Gap{Code: "modified_component", File: c.Source.File, Package: c.Name, Message: c.Name + ": modified copy; upstream advisories do not cover changes in this copy. Review its code and upstream fixes."})
		}
	}
	open, policy := 0, false
	for _, f := range r.Findings {
		if f.Component.Shipped != nil && !*f.Component.Shipped {
			continue
		}
		if !Resolved(f) {
			open++
			policy = policy || f.KnownExploited
		}
	}
	vulnState := Evidenced
	if open > 0 || len(r.CoverageGaps) > 0 || !r.ScanComplete {
		vulnState = Review
	}
	vulnExplanation := fmt.Sprintf("%d open advisory groups in shipped or possibly shipped components. Coverage gaps: %d. %s", open, len(uniqueGaps(r.CoverageGaps)), Scope)
	if !r.ScanComplete {
		vulnExplanation = "Scan evidence is incomplete or stale; saved finding counts do not show current coverage. " + strings.Join(r.ScanIssues, " ") + " " + vulnExplanation
	}
	add("Known vulnerabilities", vulnState, vulnExplanation, "Review cra/reports/vulnerabilities.md; record decisions with conformline triage and run conformline scan for incomplete evidence.")
	r.CoverageGaps = uniqueGaps(r.CoverageGaps)
	docItem("Support period", "cra/support-period.md")
	if p.Support.End == nil {
		r.Items[len(r.Items)-1].State = Missing
		r.Items[len(r.Items)-1].Explanation = "The support end date is unknown."
		r.Items[len(r.Items)-1].Action = "Decide support.end in cra.yml and review cra/support-period.md."
	}
	docItem("User information", "cra/user-information.md")
	docItem("Risk assessment", "cra/risk-assessment.md")
	docItem("Technical documentation", "cra/technical-documentation.md")
	docItem("EU declaration of conformity", "cra/eu-declaration-of-conformity.md")
	r.Items[len(r.Items)-1].Explanation += " Draft, not signed; sign before placing on the market from December 11, 2027."
	if assessment {
		r.Items[len(r.Items)-1].Explanation += " " + Assessment + " " + AssessmentURL
	}
	docItem("Incident readiness", "cra/incident-checklist.md")
	add("Open incidents", NA, "none", "No action needed.")
	if p.Role.Answer == "not-in-scope" {
		for i := range r.Items {
			if i != 0 && i != 4 && i != 5 {
				r.Items[i].State = NA
				r.Items[i].Explanation = "Not applicable to your recorded not-in-scope role."
				r.Items[i].Action = "No action needed."
			}
		}
	}
	actions := rankActions(r)
	for _, a := range actions {
		if len(r.Next) == 5 {
			break
		}
		if !slices.Contains(r.Next, a.text) {
			r.Next = append(r.Next, a.text)
		}
	}
	if policy {
		r.ExitCode = 10
	}
	if strict {
		for _, it := range r.Items {
			if it.State == Missing {
				r.ExitCode = 10
			}
		}
	}
	if r.ExitCode == 0 && !r.ScanComplete {
		r.ExitCode = 11
	}
	return r, nil
}
func uniqueGaps(in []inventory.Gap) []inventory.Gap {
	out := []inventory.Gap{}
	for _, g := range in {
		if !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	return out
}
func Resolved(f vulns.Finding) bool { return f.Status == "fixed" || f.Status == "not_affected" }

type action struct {
	text                  string
	rank, severity, count int
	name                  string
}

func severity(f vulns.Finding) int {
	highest := 0
	for _, a := range f.Advisories {
		n := map[string]int{"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1}[strings.ToLower(vulns.Rating(a, f.Component))]
		highest = max(highest, n)
	}
	return highest
}
func rankActions(r Result) []action {
	actions := []action{}
	groups := map[string][]vulns.Finding{}
	for _, f := range r.Findings {
		if !Resolved(f) && (f.Component.Shipped == nil || *f.Component.Shipped) {
			groups[f.Component.PURL] = append(groups[f.Component.PURL], f)
		}
	}
	for _, findings := range groups {
		c := findings[0].Component
		rank, sev := 3, 0
		hasFix := false
		for _, f := range findings {
			if f.KnownExploited {
				rank = 0
			}
			sev = max(sev, severity(f))
			for _, a := range f.Advisories {
				hasFix = hasFix || len(vulns.Fixed(a, c)) > 0
			}
		}
		if rank != 0 && !hasFix {
			rank = 4
		}
		verb := "Update "
		if !hasFix {
			verb = "Review "
		}
		text := fmt.Sprintf("%s%s %s", verb, inventory.LibraryDisplayName(c.Name), Value(c.Version))
		fix := vulns.SafeFix(c, findings)
		if fix != "" {
			text = fmt.Sprintf("Update %s from %s to %s", inventory.LibraryDisplayName(c.Name), Value(c.Version), fix)
		}
		paths := []string{}
		for _, ev := range c.Evidence {
			if ev.Path != "" && !slices.Contains(paths, ev.Path) {
				paths = append(paths, ev.Path)
			}
		}
		if len(paths) > 0 {
			text += " in " + strings.Join(paths, ", ")
		}
		label := "advisories"
		if len(findings) == 1 {
			label = "advisory"
		}
		text += fmt.Sprintf(" (%d %s).", len(findings), label)
		if fix == "" {
			text += " " + vulns.Advice(c, findings)
		}
		if rank == 0 {
			text = "Known exploited: " + text
		}
		actions = append(actions, action{text, rank, sev, len(findings), c.Name + " " + c.PURL})
	}
	for i, it := range r.Items {
		if it.State == Evidenced || it.State == NA {
			continue
		}
		rank := 5
		if it.State == Missing {
			rank = 6
		}
		if i == 0 {
			rank = 4
		}
		if i == 1 || (i == 4 && r.Product.Version == nil) || (i == 6 && it.State == Missing) {
			rank = 4
		}
		name := it.Name
		if i == 0 {
			name = ""
		}
		if r.Strict && it.State == Missing {
			rank = 0
		}
		actions = append(actions, action{it.Action, rank, 0, 0, name})
	}
	slices.SortStableFunc(actions, func(a, b action) int {
		if a.rank != b.rank {
			return a.rank - b.rank
		}
		if a.rank == 4 && (a.name == "" || b.name == "") {
			return strings.Compare(a.name, b.name)
		}
		if a.severity != b.severity {
			return b.severity - a.severity
		}
		if a.count != b.count {
			return b.count - a.count
		}
		return strings.Compare(a.name, b.name)
	})
	return actions
}

func sentence(text string) string {
	text = strings.TrimSpace(text)
	if text != "" && !strings.ContainsAny(text[len(text)-1:], ".!?") {
		text += "."
	}
	return text
}
