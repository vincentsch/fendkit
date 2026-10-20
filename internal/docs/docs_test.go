package docs

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincentsch/conformline/internal/detect"
	"github.com/vincentsch/conformline/internal/profile"
	"github.com/vincentsch/conformline/internal/version"
	"gopkg.in/yaml.v3"
)

func TestDocumentsPreserveMakerEdits(t *testing.T) {
	root := t.TempDir()
	original := []byte("# Our existing security policy\nEmail security@example.com.\n")
	if err := os.WriteFile(filepath.Join(root, "SECURITY.md"), original, 0644); err != nil {
		t.Fatal(err)
	}
	p := &profile.Profile{Version: 1, Role: profile.Role{Answer: "manufacturer"}, Product: profile.Product{Name: detect.String("Booking"), Type: detect.String("wordpress-plugin")}, SecurityContact: profile.Contact{Email: detect.String("security@example.com"), URL: detect.String("https://example.com/report"), PolicyURL: detect.String("https://example.com/disclosure")}, Manufacturer: profile.Manufacturer{Website: detect.String("https://example.com/product")}}
	now := time.Date(2026, 10, 20, 10, 30, 0, 0, time.UTC)
	r, err := Generate(root, p, now, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Created) != 8 || len(r.Existing) != 1 {
		t.Fatalf("%+v", r)
	}
	hashes := map[string][32]byte{}
	for _, file := range Files {
		path := filepath.Join(root, file)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if file != "SECURITY.md" {
			b = append(b, []byte("\nMaker reviewed this paragraph.\n")...)
			if err = os.WriteFile(path, b, 0644); err != nil {
				t.Fatal(err)
			}
		}
		hashes[file] = sha256.Sum256(b)
	}
	r, err = Generate(root, p, now.AddDate(0, 0, 1), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Created) != 0 || len(r.Existing) != 9 {
		t.Fatalf("%+v", r)
	}
	for file, hash := range hashes {
		b, _ := os.ReadFile(filepath.Join(root, file))
		if sha256.Sum256(b) != hash {
			t.Fatal("overwrote", file)
		}
	}
	p.Role.Answer = "not-in-scope"
	r, err = Generate(root, p, now, false)
	if err != nil || len(r.Created) != 0 || len(r.Existing) != 9 {
		t.Fatalf("%+v %v", r, err)
	}
	for file, hash := range hashes {
		b, _ := os.ReadFile(filepath.Join(root, file))
		if sha256.Sum256(b) != hash {
			t.Fatal("out-of-scope changed", file)
		}
	}
	b, _ := os.ReadFile(filepath.Join(root, "cra/README.md"))
	if strings.Contains(string(b), "## Publish the reporting contact") {
		t.Fatal("publishing instructions for a skipped obligation")
	}
	if !strings.Contains(string(b), "existing; review metadata not set") {
		t.Fatal(string(b))
	}

}
func TestTemplateSectionsAndLegalWording(t *testing.T) {
	p := &profile.Profile{Version: 1, Role: profile.Role{Answer: "unknown"}, Classification: profile.Classification{Answer: "unknown"}}
	root := t.TempDir()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	if _, err := Generate(root, p, now, false); err != nil {
		t.Fatal(err)
	}
	headings := map[string][]string{
		"SECURITY.md":                         {"Contact", "What to send", "What to expect", "Disclosure policy"},
		"cra/disclosure-policy.md":            {"Scope", "How to report", "Response times", "Safe harbour", "Credit"},
		"cra/support-period.md":               {"Product and version line", "End date and expected use", "Security updates"},
		"cra/user-information.md":             {"1. Manufacturer and contact", "2. Reporting vulnerabilities", "3. Product identity", "4. Purpose and security environment", "5. Risks and foreseeable misuse", "6. EU declaration", "7. Security support", "8. Secure use throughout the product lifetime", "9. Software bill of materials"},
		"cra/technical-documentation.md":      {"1. General description", "2. Design, development, production and vulnerability handling", "3. Cybersecurity risk assessment", "4. Basis for the support period", "5. Standards and specifications", "6. Test reports", "7. EU declaration", "8. SBOM for authorities"},
		"cra/eu-declaration-of-conformity.md": {"1. Product identity", "2. Manufacturer", "3. Sole responsibility", "4. Object and traceability", "5. Relevant Union legislation", "6. Standards and specifications", "7. Notified body", "8. Additional information and signing"},
		"cra/risk-assessment.md":              {"Intended purpose and use environment", "Assets", "Threats", "Appropriate security for the risks", "(a) Known exploitable vulnerabilities", "(b) Secure defaults and reset", "(c) Security updates", "(d) Unauthorised access", "(e) Confidentiality", "(f) Integrity", "(g) Data minimisation", "(h) Availability", "(i) Effects on other systems", "(j) Attack surfaces", "(k) Exploit mitigation", "(l) Security activity records", "(m) Removal and transfer of data", "Third-party components and due diligence"},
		"cra/incident-checklist.md":           {"Record when you became aware", "Early warning within 24 hours", "Notification within 72 hours", "Final report", "Submit through ENISA", "Tell affected users", "Application dates"},
	}
	for _, file := range append(append([]string{}, Files...), "cra/README.md") {
		b, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		for _, bad := range []string{"compliant product", "cra compliant", "certified", "guarantee", "ensures compliance", "cra-ready"} {
			if strings.Contains(strings.ToLower(text), bad) {
				t.Fatalf("%s: forbidden wording %s", file, bad)
			}
		}
		for _, heading := range headings[file] {
			if !strings.Contains(text, "## "+heading+"\n") {
				t.Fatalf("%s missing heading %s", file, heading)
			}
		}
		if !strings.Contains(text, "Requirement:") {
			t.Fatal(file, "missing source")
		}
		if file != "cra/README.md" && file != "cra/security.txt" {
			if !strings.HasPrefix(text, "---\n") {
				t.Fatal(file, "missing metadata")
			}
			parts := strings.SplitN(text, "---", 3)
			var m map[string]string
			if err := yaml.Unmarshal([]byte(parts[1]), &m); err != nil || m["status"] != "draft" || m["conformline"] != version.Version || m["reviewed_on"] != "" || m["reviewed_by"] != "" {
				t.Fatalf("%s: %v %v", file, m, err)
			}
			if !strings.Contains(text, "[[") {
				t.Fatal(file, "missing unknown placeholders")
			}
		}
	}
	index, err := os.ReadFile(filepath.Join(root, "cra/README.md"))
	if err != nil {
		t.Fatal(err)
	}
	// Normalise wrapping so the assertions protect meaning across paragraph edits.
	indexText := strings.Join(strings.Fields(string(index)), " ")
	for _, required := range []string{
		"Conformline helps prepare evidence and does not give legal advice.",
		"A scan without findings does not prove the absence of vulnerabilities.",
		"As of October 20, 2026, no harmonised CRA standard is cited in the Official Journal, so no presumption of conformity is available from one.",
		"The Commission guidance C(2026) 5252 of July 27, 2026 is non-binding.",
		"The EU declaration remains an unsigned draft until a responsible person reviews and signs it.",
	} {
		if !strings.Contains(indexText, required) {
			t.Fatalf("index missing required statement: %s", required)
		}
	}
	b, _ := os.ReadFile(filepath.Join(root, "cra/eu-declaration-of-conformity.md"))
	if !strings.Contains(string(b), "Draft, not signed") || !strings.Contains(string(b), "Place:\n\nDate:\n\nSignature:\n") {
		t.Fatal(string(b))
	}
	for i := 1; i <= 8; i++ {
		b, _ := os.ReadFile(filepath.Join(root, "cra/technical-documentation.md"))
		if !strings.Contains(string(b), "### 2."+string(rune('0'+i))+".") {
			t.Fatal("missing vulnerability handling point", i)
		}
	}
}
func TestSecurityTextFields(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	p := &profile.Profile{SecurityContact: profile.Contact{Email: detect.String("security@example.com"), URL: detect.String("https://example.com/report"), PolicyURL: detect.String("https://example.com/policy")}, Manufacturer: profile.Manufacturer{Website: detect.String("https://example.com/product?x=1")}}
	text := securityFields(data{P: p, Now: now})
	fields := map[string][]string{}
	for _, line := range strings.Split(text, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ": ")
		if !ok {
			t.Fatal("not a field", line)
		}
		fields[key] = append(fields[key], value)
	}
	if len(fields["Contact"]) != 2 || fields["Contact"][0] != "mailto:security@example.com" || fields["Canonical"][0] != "https://example.com/.well-known/security.txt" {
		t.Fatal(text)
	}
	expires, err := time.Parse(time.RFC3339, fields["Expires"][0])
	if err != nil || expires.Sub(now) != 364*24*time.Hour {
		t.Fatal(text, err)
	}
	if strings.Contains(text, "---") {
		t.Fatal("YAML front matter")
	}
	if !strings.Contains(text, "# status: draft") {
		t.Fatal("missing review comments")
	}
	p.SecurityContact.URL = detect.String("http://insecure.example")
	p.SecurityContact.Email = nil
	text = securityFields(data{P: p, Now: now})
	if strings.Contains(text, "\nContact: ") {
		t.Fatal("fabricated contact", text)
	}
}
func TestRoleBranchesAndDryRun(t *testing.T) {
	for _, role := range []string{"manufacturer", "unknown", "not-in-scope", "open-source-steward"} {
		t.Run(role, func(t *testing.T) {
			root := t.TempDir()
			p := &profile.Profile{Role: profile.Role{Answer: role}}
			if _, err := Generate(root, p, time.Now(), true); err != nil {
				t.Fatal(err)
			}
			entries, _ := os.ReadDir(root)
			if len(entries) != 0 {
				t.Fatal("dry run wrote files")
			}
			r, err := Generate(root, p, time.Now(), false)
			if err != nil {
				t.Fatal(err)
			}
			if role == "not-in-scope" && (len(r.Created) != 0 || r.Message == "") {
				t.Fatalf("%+v", r)
			}
			if role != "not-in-scope" && len(r.Created) != 9 {
				t.Fatalf("%+v", r)
			}
			if role == "unknown" && !strings.Contains(r.Message, "first") {
				t.Fatal(r.Message)
			}
			if role == "open-source-steward" && !strings.Contains(r.Message, "Art. 24") {
				t.Fatal(r.Message)
			}
		})
	}
}

func TestReportDatesFromContent(t *testing.T) {
	root := t.TempDir()
	samples := map[string]string{
		"inventory.json":     `{"scanned_at":"2026-10-20T12:00:00Z","complete":false}`,
		"sbom.cdx.json":      `{"metadata":{"timestamp":"2026-10-20T12:00:00Z","properties":[{"name":"conformline:complete","value":"false"}]}}`,
		"vulnerabilities.md": "Scan abc is **incomplete**. Scanned at 2026-10-20T12:00:00Z.\n",
		"vex.openvex.json":   `{"statements":[{"timestamp":"2026-10-20T12:00:00Z"}]}`,
	}
	for file, text := range samples {
		path := filepath.Join(root, file)
		if err := os.WriteFile(path, []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
		label := reportDescription(path)
		if !strings.Contains(label, "2026-10-20T12:00:00Z") {
			t.Fatalf("%s: %s", file, label)
		}
		if file != "vex.openvex.json" && !strings.Contains(label, "incomplete") {
			t.Fatal(file, label)
		}
	}
}

func TestIndexUsesSavedStatusTimeAndEscapesActions(t *testing.T) {
	root := t.TempDir()
	p := &profile.Profile{Version: 1, Role: profile.Role{Answer: "not-in-scope"}}
	reportDir := filepath.Join(root, "cra/reports")
	if e := os.MkdirAll(reportDir, 0755); e != nil {
		t.Fatal(e)
	}
	for _, file := range []string{"status.md", "status.html"} {
		if e := os.WriteFile(filepath.Join(reportDir, file), []byte("# Status\n\nScan: 2026-10-20 12:00 UTC, incomplete or stale\n"), 0644); e != nil {
			t.Fatal(e)
		}
	}
	if e := WriteIndex(root, p, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), []string{"Review <adapter> & [source](https://example.com)."}, false); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(root, "cra/README.md"))
	if e != nil {
		t.Fatal(e)
	}
	text := string(b)
	if strings.Count(text, "Scan: 2026-10-20 12:00 UTC, incomplete or stale") != 2 || strings.Contains(text, "2026-11-01") || strings.Contains(text, "<adapter>") || !strings.Contains(text, "&lt;adapter&gt;") {
		t.Fatal(text)
	}
	if e = WriteIndex(root, p, time.Now(), []string{}, false); e != nil {
		t.Fatal(e)
	}
	b, e = os.ReadFile(filepath.Join(root, "cra/README.md"))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(b), "No outstanding actions.") {
		t.Fatal(string(b))
	}
}
