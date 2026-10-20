package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	input := `# My evidence
version: 1
product:
  name: Booking # keep the name
  version: null # detected
  release: dist/booking-{version}.zip
role:
  answer: unknown
  answers: {sold: null, paid_edition: false}
classification:
  answer: default
  categories: []
support:
  end: 2031-10-31
components:
  # Keep this occurrence
  - name: '@maker/tool'
    version: v1.0.0
    ecosystem: npm
    purl: pkg:npm/%40maker/tool@1.0.0
    path: assets/tool.js
    shipped: true # checked in release
    note: Copied by hand
triage:
  - advisory: GHSA-example
    component: pkg:npm/tool@1.0.0
    status: not_affected
    justification: vulnerable_code_not_present
    reason: The affected code is absent
    decided_on: 2026-10-20
`
	p, e := Parse([]byte(input))
	if e != nil {
		t.Fatal(e)
	}
	v := "2.0.0"
	p.Product.Version = &v
	file := filepath.Join(t.TempDir(), "cra.yml")
	if e = p.Save(file); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	for _, comment := range []string{"# My evidence", "# keep the name", "# detected", "# Keep this occurrence", "# checked in release"} {
		if !strings.Contains(string(b), comment) {
			t.Fatalf("lost %s", comment)
		}
	}
	again, e := Load(file)
	if e != nil {
		t.Fatal(e)
	}
	if *again.Product.Version != v || again.Role.Answers.Sold != nil || again.Role.Answers.PaidEdition == nil || *again.Role.Answers.PaidEdition || len(again.Triage) != 1 || len(again.Components) != 1 {
		t.Fatal("profile values lost")
	}
	t.Run("first entries keep inline comments", func(t *testing.T) {
		for _, input := range []string{
			"version: 1\ncomponents: [] # manual entries\ntriage: [] # advisory decisions\nmanufacturer: null # maker details\n",
			"version: 1\ncomponents: [] # manual entries\n",
		} {
			p, e := Parse([]byte(input))
			if e != nil {
				t.Fatal(e)
			}
			name, version, eco := "maker/library", "1.0.0", "composer"
			advisory, status, reason := "GHSA-example", "under_investigation", "Reviewing use"
			p.Manufacturer.Name = &name
			p.Components = []Component{{Name: &name, Version: &version, Ecosystem: &eco}}
			component, date := "pkg:composer/maker/library@1.0.0", "2026-10-20"
			p.Triage = []Triage{{Advisory: &advisory, Component: &component, Status: &status, Reason: &reason, DecidedOn: &date}}
			file := filepath.Join(t.TempDir(), "cra.yml")
			for save := 0; save < 2; save++ {
				if e = p.Save(file); e != nil {
					t.Fatal(e)
				}
				b, e := os.ReadFile(file)
				if e != nil {
					t.Fatal(e)
				}
				if !strings.Contains(string(b), "components: # manual entries\n") || strings.Count(string(b), "# manual entries") != 1 {
					t.Fatalf("component comment lost or moved:\n%s", b)
				}
				if strings.Contains(input, "# advisory decisions") && (!strings.Contains(string(b), "triage: # advisory decisions\n") || strings.Count(string(b), "# advisory decisions") != 1) {
					t.Fatalf("triage comment lost or moved:\n%s", b)
				}
				if strings.Contains(input, "# maker details") && !strings.Contains(string(b), "manufacturer: # maker details\n") {
					t.Fatalf("mapping comment lost or moved:\n%s", b)
				}
				p, e = Load(file)
				if e != nil {
					t.Fatal(e)
				}
				if len(p.Components) != 1 || len(p.Triage) != 1 {
					t.Fatal("first entries lost")
				}
			}
		}
	})
}
func TestNumericTextFields(t *testing.T) {
	for _, version := range []string{"5.3", "2", "1.10"} {
		t.Run(version, func(t *testing.T) {
			p, e := Parse([]byte("version: 1\nproduct: {version: " + version + "}\nsupport: {versions: 2}\ncomponents: [{version: 2.24}]\n"))
			if e != nil {
				t.Fatal(e)
			}
			if p.Product.Version == nil || *p.Product.Version != version || p.Support.Versions == nil || *p.Support.Versions != "2" || p.Components[0].Version == nil || *p.Components[0].Version != "2.24" {
				t.Fatalf("numeric text changed: %+v", p)
			}
			file := filepath.Join(t.TempDir(), "cra.yml")
			if e = p.Save(file); e != nil {
				t.Fatal(e)
			}
			again, e := Load(file)
			if e != nil {
				t.Fatal(e)
			}
			if *again.Product.Version != version {
				t.Fatalf("version changed after save: %q", *again.Product.Version)
			}
		})
	}
}

func TestInvalidFields(t *testing.T) {
	for _, tc := range []struct{ yaml, path string }{
		{"version: 2", "version"}, {"version: 1\nproduct: {type: plugin}", "product.type"}, {"version: 1\nrole: {answer: yes}", "role.answer"}, {"version: 1\nclassification: {answer: low}", "classification.answer"}, {"version: 1\nsupport: {end: 2026-02-30}", "support.end"}, {"version: 1\nrole: {decided_on: yesterday}", "role.decided_on"}, {"version: 1\ntriage: [{status: ignored}]", "triage[0].status"}, {"version: 1\ntriage: [{justification: safe}]", "triage[0].justification"}, {"version: 1\ncomponents: [{shipped: unknown}]", "components[0].shipped"}, {"version: 1\nproduct: {version: [1, 2]}", "product.version"}, {"version: 1\nrole: {answers: {sold: maybe}}", "role.answers.sold"}, {"version: 1\nproduct: {versoin: '1'}", "product.versoin"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			_, e := Parse([]byte(tc.yaml))
			if e == nil || !strings.Contains(e.Error(), tc.path) || !strings.Contains(e.Error(), ";") {
				t.Fatalf("expected actionable field error, got %v", e)
			}
		})
	}
}
func TestUnknownFacts(t *testing.T) {
	p, e := Parse([]byte("version: 1\nproduct: null\nrole: null\nclassification: null\n"))
	if e != nil {
		t.Fatal(e)
	}
	if p.Product.Version != nil || p.Role.Answer != "unknown" || p.Classification.Answer != "unknown" {
		t.Fatal("unknown values changed")
	}
}
