package incident

import (
	"strings"
	"testing"

	"github.com/vincentsch/fendkit/internal/detect"
	"github.com/vincentsch/fendkit/internal/inventory"
	"github.com/vincentsch/fendkit/internal/profile"
	"github.com/vincentsch/fendkit/internal/vulns"
)

func TestDraftContentAndSavedAdvisory(t *testing.T) {
	p := &profile.Profile{Product: profile.Product{Name: detect.String("Maker product"), Version: detect.String("2.3.1")}, Manufacturer: profile.Manufacturer{Name: detect.String("Maker Ltd"), Address: detect.String("Example Street"), Website: detect.String("https://example.com")}, Classification: profile.Classification{Answer: "default"}, SecurityContact: profile.Contact{Email: detect.String("security@example.com")}}
	a := vulns.Advisory{ID: "GHSA-example", Summary: "Saved advisory summary"}
	a.DatabaseSpecific.Severity = "HIGH"
	finding := vulns.Finding{IDs: []string{a.ID, "CVE-example"}, Advisories: []vulns.Advisory{a}, Component: inventory.Component{Name: "library", Version: detect.String("1.0.0")}}
	for _, kind := range []string{Exploited, Severe} {
		r := record(t, kind, "2026-10-20T10:00:00Z", "UTC")
		r.Advisory = detect.String("CVE-example")
		drafts := Drafts(r, p, detect.Product{Name: detect.String("Detected name")}, []vulns.Finding{finding})
		if len(drafts) != 4 {
			t.Fatal(drafts)
		}
		for name, text := range drafts {
			if !strings.HasPrefix(text, "Awareness time:") || !strings.Contains(text, "before filing.\n\n"+Legal+"\n\n# ") {
				t.Fatalf("%s: opening guidance must lead directly into the filing text", name)
			}
			for _, required := range []string{"Awareness time: 2026-10-20", "Current deadlines: `fendkit incident show inc-1`", "ENISA's Single Reporting Platform", "Maker product 2.3.1", "Maker Ltd", "Example Street", "Saved advisory summary", "HIGH", "CVE-example", "[[", Legal} {
				if !strings.Contains(text, required) {
					t.Fatalf("%s missing %q", name, required)
				}
			}
			if strings.Contains(text, "Detected name") || strings.Contains(text, "2026-10-21") {
				t.Fatal("incorrect prefill or moving deadline in draft", name)
			}
			for _, bad := range []string{"compliant product", "cra compliant", "certified", "guarantee", "ensures compliance", "cra-ready"} {
				if strings.Contains(strings.ToLower(text), bad) {
					t.Fatal(name, bad)
				}
			}
		}
		for _, required := range []string{"Nature and initial assessment", "Exploit details", "Corrective or mitigating measures", "Measures users can take", "Product category under Annex III/IV", "Information sensitivity"} {
			if !strings.Contains(drafts["notification.md"], required) {
				t.Fatal(required)
			}
		}
		finalSections := []string{"severity and impact", "Malicious actor", "Security update or other measures", "Art. 14(2)(c)"}
		if kind == Severe {
			finalSections = []string{"severity and impact", "Threat or root cause", "Applied and ongoing mitigation", "Art. 14(4)(c)"}
		}
		for _, required := range finalSections {
			if !strings.Contains(drafts["final-report.md"], required) {
				t.Fatal(required)
			}
		}
		for _, required := range []string{"without undue delay", "protective steps", "machine-readable", "security@example.com", "Art. 14(8)"} {
			if !strings.Contains(drafts["user-notice.md"], required) {
				t.Fatal(required)
			}
		}
	}
}
