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

	"github.com/vincentsch/fendkit/internal/detect"
	"github.com/vincentsch/fendkit/internal/docs"
	"github.com/vincentsch/fendkit/internal/incident"
	"github.com/vincentsch/fendkit/internal/inventory"
	"github.com/vincentsch/fendkit/internal/profile"
	"github.com/vincentsch/fendkit/internal/vulns"
	"gopkg.in/yaml.v3"
)

type State string

const (
	Evidenced State = "evidenced"
	Review    State = "needs review"
	Missing   State = "missing"
	NA        State = "not applicable"
)
const Assessment = "Your classification may require a conformity assessment by a third party. Fendkit does not prepare or assess that procedure."
const AssessmentURL = "https://digital-strategy.ec.europa.eu/en/policies/cra-conformity-assessment"
const Legal = "Not legal advice. Fendkit helps you prepare; the decisions and the signature are yours."
const Scope = "Fendkit only checks third-party components. It does not check the maker's own code for vulnerabilities. A scan without findings does not prove the absence of vulnerabilities."

const ReviewProcedure = "Review each draft and fill remaining placeholders. Set status: reviewed, reviewed_by and reviewed_on (YYYY-MM-DD) in Markdown front matter, or in # comment metadata for cra/security.txt. Publish the policy and /.well-known/security.txt over HTTPS; local review cannot verify deployment."

type itemID string
type reason string

const (
	roleItem            itemID = "role"
	classificationItem  itemID = "classification"
	securityItem        itemID = "security-contact"
	disclosureItem      itemID = "disclosure-policy"
	sbomItem            itemID = "sbom"
	vulnerabilitiesItem itemID = "known-vulnerabilities"
	supportItem         itemID = "support-period"
	userInformationItem itemID = "user-information"
	riskItem            itemID = "risk-assessment"
	technicalItem       itemID = "technical-documentation"
	declarationItem     itemID = "eu-declaration-of-conformity"
	readinessItem       itemID = "incident-readiness"
	incidentsItem       itemID = "open-incidents"
	scanRefresh         reason = "scan-refresh"
	versionRepair       reason = "version-repair"
	supportDecision     reason = "support-decision"
	documentReview      reason = "document-review"
	noIncidents         reason = "no-incidents"
)

type Item struct {
	ID          itemID `json:"id"`
	Reason      reason `json:"reason,omitempty"`
	RowAction   string `json:"-"`
	Name        string `json:"name"`
	State       State  `json:"state"`
	Explanation string `json:"explanation"`
	Action      string `json:"action"`
}
type Document struct {
	ReviewRequired bool   `json:"review_required"`
	Path           string `json:"path"`
	Status         string `json:"status"`
	ReviewedBy     string `json:"reviewed_by"`
	ReviewedOn     string `json:"reviewed_on"`
	State          State  `json:"state"`
	Explanation    string `json:"explanation"`
}
type Scan struct {
	ScanID            string    `json:"scan_id"`
	ScannedAt         time.Time `json:"scanned_at"`
	ProductVersion    *string   `json:"product_version"`
	InventoryDigest   string    `json:"inventory_digest"`
	Complete          bool      `json:"complete"`
	Offline           bool      `json:"offline"`
	IncompleteReasons []string  `json:"incomplete_reasons"`
	inventory.Inventory
}
type Result struct {
	ReviewProcedure string                `json:"review_procedure"`
	Incidents       []incident.View       `json:"incidents"`
	LegalNotice     string                `json:"legal_notice"`
	Strict          bool                  `json:"strict"`
	Product         detect.Product        `json:"product"`
	ScannedAt       time.Time             `json:"scanned_at"`
	ScanComplete    bool                  `json:"scan_complete"`
	ScanState       string                `json:"scan_state"`
	ScanDetail      string                `json:"-"`
	ScanRecovery    string                `json:"-"`
	ScanIssues      []string              `json:"scan_issues"`
	Items           []Item                `json:"items"`
	Next            []string              `json:"next_actions"`
	Components      []inventory.Component `json:"components"`
	Findings        []vulns.Finding       `json:"findings"`
	CoverageGaps    []inventory.Gap       `json:"coverage_gaps"`
	Documents       []Document            `json:"documents"`
	Notes           []string              `json:"notes"`
	ExitCode        int                   `json:"exit_code"`
	DryRun          bool                  `json:"dry_run"`
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
	d := Document{ReviewRequired: true, Path: file, Status: "missing", State: Missing, Explanation: "The file is missing."}
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
	d.Explanation = "Draft review is incomplete."
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
	d.ReviewRequired = d.State == Review || d.State == Missing
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
	r := Result{ReviewProcedure: ReviewProcedure, Incidents: []incident.View{}, LegalNotice: Legal, Strict: strict, Product: product, Next: []string{}, ScanIssues: []string{}, Notes: []string{Scope}, Items: []Item{}, Documents: []Document{}}
	bomOK, bomVersion := evaluateScan(root, p, now, &r)
	add := func(id itemID, name string, state State, explanation, action string) *Item {
		r.Items = append(r.Items, Item{ID: id, Name: name, State: state, Explanation: explanation, Action: action})
		return &r.Items[len(r.Items)-1]
	}
	decision := func(id itemID, name, answer, field string) *Item {
		if answer == "unknown" || answer == "" {
			return add(id, name, Review, "This needs your decision.", "Decide "+field+" in cra.yml.")
		}
		return add(id, name, Evidenced, "Your recorded decision: "+answer+".", "Review this decision when the product changes.")
	}
	decision(roleItem, "Role", p.Role.Answer, "role.answer")
	if p.Role.Answer == "open-source-steward" {
		r.Notes = append(r.Notes, "Fendkit v0.1 follows manufacturer preparation steps. It does not assess steward obligations under Art. 24.")
	}
	classification := decision(classificationItem, "Classification", p.Classification.Answer, "classification.answer")
	assessment := p.Classification.Answer == "important-class-i" || p.Classification.Answer == "important-class-ii" || p.Classification.Answer == "critical"
	if assessment {
		classification.Explanation += " " + Assessment + " " + AssessmentURL
	}
	documentMap := map[string]Document{}
	for _, file := range docs.Files {
		d := InspectDocument(root, file, now)
		if p.Role.Answer == "not-in-scope" {
			d.State = NA
			d.ReviewRequired = false
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
	security := add(securityItem, "Security contact", securityState, securityExplanation(sec, txt), "Review SECURITY.md and cra/security.txt, fill remaining placeholders, then set status: reviewed, reviewed_by and reviewed_on (YYYY-MM-DD) in SECURITY.md front matter and security.txt comment metadata; publish the policy and /.well-known/security.txt over HTTPS.")
	security.Reason = documentReview
	security.RowAction = "Review SECURITY.md and cra/security.txt; publish the policy and /.well-known/security.txt over HTTPS."
	docItem := func(id itemID, name, file string) *Item {
		d := documentMap[file]
		it := add(id, name, d.State, d.Explanation, "Review "+file+", fill remaining placeholders, then set status: reviewed, reviewed_by and reviewed_on (YYYY-MM-DD) in its front matter.")
		it.Reason = documentReview
		it.RowAction = "Review " + file + "."
		return it
	}
	docItem(disclosureItem, "Disclosure policy", "cra/disclosure-policy.md")
	sbomState := Evidenced
	sbomWhy := "The SBOM belongs to the current scan and product version."
	if !bomOK {
		sbomState = Missing
		sbomWhy = "The SBOM is absent or unreadable. Scan evidence is " + r.ScanDetail + "."
	} else if !r.ScanComplete || r.Product.Version == nil || bomVersion != Value(r.Product.Version) {
		sbomState = Review
		sbomWhy = "Scan evidence is " + r.ScanDetail + "."
		if r.Product.Version != nil && bomVersion != Value(r.Product.Version) {
			sbomWhy += " The SBOM product version differs from the current product version."
		}
	}
	productAction := "Run fendkit scan."
	productReason := scanRefresh
	if sbomState == Evidenced {
		productAction = "Scan again when the product or its components change, or after seven days."
	}
	if r.Product.Version == nil {
		sbomState = Review
		if !bomOK {
			sbomState = Missing
		}
		sbomWhy += " The product version is unknown."
		productReason = versionRepair
		productAction = "Set product.version in cra.yml, then run fendkit scan."
	}
	if p.Product.Version != nil && product.DetectedVersion != nil && !same(p.Product.Version, product.DetectedVersion) {
		sbomState = Review
		sbomWhy += fmt.Sprintf(" Configured product.version %s differs from detected version %s.", *p.Product.Version, *product.DetectedVersion)
		productReason = versionRepair
		productAction = "Review product.version in cra.yml and the detected version, then run fendkit scan."
	}
	for _, note := range r.Product.Notes {
		if strings.Contains(note, "Stable tag") {
			sbomState = Review
			sbomWhy += " " + note
			productReason = versionRepair
			productAction = "Review and align readme.txt Stable tag and the WordPress header, then run fendkit scan."
		}
	}
	add(sbomItem, "SBOM", sbomState, sbomWhy, productAction).Reason = productReason
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
		vulnExplanation = "Scan evidence is " + r.ScanDetail + "; saved finding counts do not show current coverage. " + strings.Join(r.ScanIssues, " ") + " " + vulnExplanation
	}
	add(vulnerabilitiesItem, "Known vulnerabilities", vulnState, vulnExplanation, "Review cra/reports/vulnerabilities.md and record decisions with fendkit triage.")
	r.CoverageGaps = uniqueGaps(r.CoverageGaps)
	support := docItem(supportItem, "Support period", "cra/support-period.md")
	if p.Support.End == nil {
		support.State = Missing
		support.Reason = supportDecision
		support.Explanation = "The support end date is unknown."
		support.Action = "Decide support.end in cra.yml. Review cra/support-period.md, fill placeholders and set status: reviewed, reviewed_by and reviewed_on (YYYY-MM-DD) in its front matter."
		support.RowAction = "Decide support.end in cra.yml and review cra/support-period.md."
	}
	docItem(userInformationItem, "User information", "cra/user-information.md")
	docItem(riskItem, "Risk assessment", "cra/risk-assessment.md")
	docItem(technicalItem, "Technical documentation", "cra/technical-documentation.md")
	declaration := docItem(declarationItem, "EU declaration of conformity", "cra/eu-declaration-of-conformity.md")
	declaration.Explanation += " Draft, not signed; sign before placing on the market from December 11, 2027."
	if assessment {
		declaration.Explanation += " " + Assessment + " " + AssessmentURL
	}
	docItem(readinessItem, "Incident readiness", "cra/incident-checklist.md")
	records, err := incident.List(root)
	if err != nil {
		return r, fmt.Errorf("cannot read incidents: %w", err)
	}
	incidentState, incidentWhy := NA, "none"
	if len(records) > 0 {
		incidentState = Evidenced
		explanations := []string{}
		for _, rec := range records {
			v := incident.Describe(rec, now)
			r.Incidents = append(r.Incidents, v)
			for _, stage := range v.Stages {
				explanations = append(explanations, sentence(rec.ID+" "+stage.Name+": "+stage.Description))
				if stage.SubmittedAt == nil {
					incidentState = Review
				}
				if stage.Overdue && p.Role.Answer != "not-in-scope" {
					policy = true
				}
			}
		}
		incidentWhy = strings.Join(explanations, " ")
	}
	incidentAction := "No action needed."
	if incidentState == Review {
		incidentAction = "Review current deadlines and filing drafts with fendkit incident show <id>; a person submits in ENISA's platform."
	}
	incidents := add(incidentsItem, "Open incidents", incidentState, incidentWhy, incidentAction)
	if len(records) == 0 {
		incidents.Reason = noIncidents
	}
	applyRole(&r, p.Role.Answer)
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
	due                   time.Time
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
	if r.ScanRecovery != "" {
		actions = append(actions, action{text: r.ScanRecovery, rank: 2})
	}
	if itemApplicable(r, incidentsItem) {
		for _, v := range r.Incidents {
			for _, s := range v.Stages {
				if s.SubmittedAt != nil {
					continue
				}
				rank := 3
				due := time.Time{}
				if s.DueAt != nil {
					due = *s.DueAt
				} else {
					rank = 5
				}
				if s.Overdue {
					rank = -1
				}
				text := fmt.Sprintf("%s %s: %s. Review %s; fendkit incident show %s.", v.Record.ID, s.Name, s.Description, s.Draft, v.Record.ID)
				actions = append(actions, action{text: text, rank: rank, name: v.Record.ID + " " + s.Name, due: due})
			}
		}
	}
	groups := map[string][]vulns.Finding{}
	for _, f := range r.Findings {
		if !Resolved(f) && (f.Component.Shipped == nil || *f.Component.Shipped) {
			groups[f.Component.PURL] = append(groups[f.Component.PURL], f)
		}
	}
	for _, findings := range groups {
		c := findings[0].Component
		rank, sev := 4, 0
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
			rank = 5
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
		actions = append(actions, action{text: text, rank: rank, severity: sev, count: len(findings), name: c.Name + " " + c.PURL})
	}
	for _, it := range r.Items {
		if it.ID == incidentsItem || it.State == Evidenced || it.State == NA || (it.Reason == scanRefresh && r.ScanRecovery != "") {
			continue
		}
		rank := 6
		if it.State == Missing {
			rank = 7
		}
		if it.ID == roleItem {
			rank = 5
		}
		if it.ID == classificationItem || (it.ID == sbomItem && r.Product.Version == nil) || (it.ID == supportItem && it.State == Missing) {
			rank = 5
		}
		name := string(it.ID)
		if it.ID == roleItem {
			name = ""
		}
		if r.Strict && it.State == Missing {
			rank = 1
		}
		actions = append(actions, action{text: it.Action, rank: rank, name: name})
	}
	slices.SortStableFunc(actions, func(a, b action) int {
		if a.rank != b.rank {
			return a.rank - b.rank
		}
		if (a.rank == -1 || a.rank == 3) && !a.due.Equal(b.due) {
			return a.due.Compare(b.due)
		}
		if a.rank == 5 && (a.name == "" || b.name == "") {
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

func securityExplanation(sec, txt Document) string {
	parts := []string{}
	for _, d := range []Document{sec, txt} {
		parts = append(parts, d.Path+": "+d.Explanation)
	}
	return strings.Join(parts, " ") + " Publication cannot be checked locally."
}

func applyRole(r *Result, role string) {
	if role != "not-in-scope" {
		return
	}
	for i := range r.Items {
		it := &r.Items[i]
		switch it.ID {
		case roleItem, sbomItem, vulnerabilitiesItem:
			continue
		}
		it.State = NA
		it.Explanation = "Not applicable to your recorded not-in-scope role."
		it.Action = "No action needed."
		it.RowAction = ""
	}
}

func itemApplicable(r Result, id itemID) bool {
	for _, it := range r.Items {
		if it.ID == id {
			return it.State != NA
		}
	}
	return false
}

func rowAction(it Item) string {
	if it.RowAction != "" {
		return it.RowAction
	}
	return it.Action
}
