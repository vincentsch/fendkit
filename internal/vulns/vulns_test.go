package vulns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vincentsch/conformline/internal/detect"
	"github.com/vincentsch/conformline/internal/inventory"
	"github.com/vincentsch/conformline/internal/profile"
	"github.com/vincentsch/conformline/internal/version"
)

func fixture(t *testing.T, id string) Advisory {
	t.Helper()
	b, e := os.ReadFile("testdata/" + id + ".json")
	if e != nil {
		t.Fatal(e)
	}
	var a Advisory
	if e = json.Unmarshal(b, &a); e != nil {
		t.Fatal(e)
	}
	return a
}
func component(name, version, eco string) inventory.Component {
	return inventory.Component{Name: name, Version: detect.String(version), LookupVersion: detect.String(version), Ecosystem: eco, PURL: inventory.PURL(eco, name, version)}
}
func guzzle() inventory.Component { return component("guzzlehttp/guzzle", "7.4.0", "composer") }
func TestGroupingFixesAndRatings(t *testing.T) {
	a, b, later := fixture(t, "GHSA-f2wf-25xc-69c9"), fixture(t, "GHSA-w248-ffj2-4v5q"), fixture(t, "GHSA-v5mv-p594-2x33")
	a.Affected[0].Versions = []string{"4.0.0-rc.1"}
	c := guzzle()
	groups := Group(c, []Advisory{a, b}, map[string]bool{"CVE-2022-31042": true})
	if len(groups) != 1 || len(groups[0].Advisories) != 2 || !groups[0].KnownExploited || !slices.Contains(groups[0].IDs, b.ID) {
		t.Fatalf("wrong alias group: %+v", groups)
	}
	if fix := SafeFix(c, groups); fix != "7.4.4" {
		t.Fatalf("wrong branch fix %q", fix)
	}
	groups = append(groups, Group(c, []Advisory{later}, nil)...)
	if fix := SafeFix(c, groups); fix != "7.15.2" {
		t.Fatalf("wrong combined fix %q", fix)
	}
	if strings.Contains(Advice(c, groups), "or later") || Rating(a, c) != "HIGH" {
		t.Fatal("wrong advice or rating")
	}
	c.Modified = true
	if SafeFix(c, groups) != "" {
		t.Fatal("modified copies need source review")
	}
	c.Modified = false
	uncertain := later
	uncertain.Affected[0].Ranges[0].Events = []Event{{Introduced: "0"}}
	if SafeFix(c, append(groups, Group(c, []Advisory{uncertain}, nil)...)) != "" {
		t.Fatal("open range must block advice")
	}
	downgrade := guzzle()
	downgrade.Version = detect.String("7.5.0")
	downgrade.LookupVersion = downgrade.Version
	if SafeFix(downgrade, Group(downgrade, []Advisory{a}, nil)) != "" {
		t.Fatal("downgrade proposed")
	}
	a.DatabaseSpecific.Severity = ""
	if !strings.Contains(Rating(a, c), "not rated (CVSS:") {
		t.Fatal("lost source vector")
	}
	a.Severity = nil
	if Rating(a, c) != "not rated" {
		t.Fatal("invented rating")
	}
	bridge := Advisory{ID: "C", Aliases: []string{"A", "B"}}
	if len(Group(c, []Advisory{{ID: "A"}, {ID: "B"}, bridge}, nil)) != 1 {
		t.Fatal("transitive grouping failed")
	}
}
func TestLookupPaginationCacheAndFailures(t *testing.T) {
	a, b := fixture(t, "GHSA-f2wf-25xc-69c9"), fixture(t, "GHSA-w248-ffj2-4v5q")
	var calls atomic.Int32
	var fail atomic.Bool
	var detailCalls atomic.Int32
	var mu sync.Mutex
	querySizes := []int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "conformline/"+version.Version {
			t.Errorf("User-Agent = %q", got)
		}
		calls.Add(1)
		if r.URL.Path == "/kev" {
			if fail.Load() {
				w.WriteHeader(503)
				return
			}
			data, _ := os.ReadFile("testdata/kev.json")
			w.Write(data)
			return
		}
		if r.URL.Path == "/v1/querybatch" {
			var q struct {
				Queries []query `json:"queries"`
			}
			if json.NewDecoder(r.Body).Decode(&q) != nil {
				t.Error("invalid query")
			}
			mu.Lock()
			querySizes = append(querySizes, len(q.Queries))
			mu.Unlock()
			results := []any{}
			for index, entry := range q.Queries {
				if entry.Package.Name != "guzzlehttp/guzzle" || entry.Package.Ecosystem != "Packagist" || entry.Version != "7.4.0" {
					t.Error("wrong lookup")
				}
				id := a.ID
				next := ""
				if index == 0 && entry.PageToken == "" {
					next = "next"
				}
				if entry.PageToken != "" {
					id = b.ID
					next = ""
				}
				results = append(results, map[string]any{"vulns": []any{map[string]string{"id": id}}, "next_page_token": next})
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
			return
		}
		detailCalls.Add(1)
		switch r.URL.Path {
		case "/v1/vulns/" + a.ID:
			json.NewEncoder(w).Encode(a)
		case "/v1/vulns/" + b.ID:
			json.NewEncoder(w).Encode(b)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client := &Client{HTTP: server.Client(), OSV: server.URL, KEV: server.URL + "/kev"}
	c := guzzle()
	other := c
	other.PURL = "pkg:composer/guzzlehttp/guzzle@v7.4.0"
	inv := inventory.Inventory{Components: []inventory.Component{c, other, {Name: "unknown", Ecosystem: "npm"}, {Name: "selectwoo", Version: detect.String("1.0.1"), Ecosystem: "github"}}}
	findings, reasons := client.Lookup(context.Background(), inv, false)
	if len(reasons) != 0 || len(findings) != 2 || detailCalls.Load() != 2 || !findings[0].KnownExploited {
		t.Fatalf("findings=%+v reasons=%v detail calls=%d", findings, reasons, detailCalls.Load())
	}
	fail.Store(true)
	_, reasons = client.Lookup(context.Background(), inv, false)
	if len(reasons) != 1 || !strings.Contains(reasons[0], "CISA KEV") {
		t.Fatal(reasons)
	}
	before := calls.Load()
	_, reasons = client.Lookup(context.Background(), inv, true)
	if len(reasons) != 1 || calls.Load() != before {
		t.Fatal("offline made requests")
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(querySizes, []int{2, 1, 2, 1}) {
		t.Fatal(querySizes)
	}
}
func TestBatchLimitAndDetailConcurrency(t *testing.T) {
	var active, peak atomic.Int32
	var batchesMu sync.Mutex
	sizes := []int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev":
			fmt.Fprint(w, `{"vulnerabilities":[]}`)
		case "/v1/querybatch":
			var q struct{ Queries []query }
			json.NewDecoder(r.Body).Decode(&q)
			batchesMu.Lock()
			sizes = append(sizes, len(q.Queries))
			batchesMu.Unlock()
			results := []any{}
			for i := range q.Queries {
				results = append(results, map[string]any{"vulns": []any{map[string]string{"id": fmt.Sprintf("advisory-%d", i%20)}}})
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		default:
			n := active.Add(1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			defer active.Add(-1)
			json.NewEncoder(w).Encode(Advisory{ID: strings.TrimPrefix(r.URL.Path, "/v1/vulns/"), Affected: []Affected{}})
		}
	}))
	defer server.Close()
	inv := inventory.Inventory{}
	for range 1001 {
		inv.Components = append(inv.Components, guzzle())
	}
	_, reasons := (&Client{HTTP: server.Client(), OSV: server.URL, KEV: server.URL + "/kev"}).Lookup(context.Background(), inv, false)
	if len(reasons) > 0 || !slices.Equal(sizes, []int{1000, 1}) || peak.Load() > 8 || peak.Load() < 2 {
		t.Fatalf("%v %v peak %d", reasons, sizes, peak.Load())
	}
}
func TestFailedDetailsAndMalformedBatch(t *testing.T) {
	for _, mode := range []string{"details", "batch", "count", "kev"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/kev":
					if mode == "kev" {
						fmt.Fprint(w, `{}`)
					} else {
						fmt.Fprint(w, `{"vulnerabilities":[]}`)
					}
				case "/v1/querybatch":
					if mode == "batch" {
						requests.Add(1)
						w.WriteHeader(503)
					} else if mode == "count" {
						fmt.Fprint(w, `{"results":[]}`)
					} else {
						fmt.Fprint(w, `{"results":[{"vulns":[{"id":"missing"}]}]}`)
					}
				default:
					requests.Add(1)
					w.WriteHeader(503)
				}
			}))
			defer server.Close()
			_, reasons := (&Client{HTTP: server.Client(), OSV: server.URL, KEV: server.URL + "/kev"}).Lookup(context.Background(), inventory.Inventory{Components: []inventory.Component{guzzle()}}, false)
			if len(reasons) == 0 {
				t.Fatal("failed request appeared complete")
			}
			if mode == "details" || mode == "batch" {
				if requests.Load() != 3 {
					t.Fatalf("wanted two retries, got %d requests", requests.Load())
				}
			}
		})
	}
}
func ValidateVEX(t *testing.T, b []byte) map[string]any {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	schema, e := compiler.Compile("../../testdata/schema/openvex-0.2.0.schema.json")
	if e != nil {
		t.Fatal(e)
	}
	var value any
	if e = json.Unmarshal(b, &value); e != nil {
		t.Fatal(e)
	}
	if e = schema.Validate(value); e != nil {
		t.Fatal(e)
	}
	return value.(map[string]any)
}
func TestDecisionsAndVEX(t *testing.T) {
	c := guzzle()
	a := fixture(t, "GHSA-f2wf-25xc-69c9")
	r := Report{ScanID: "saved", ScannedAt: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC), ProductPURL: "pkg:generic/acme-booking@2.3.1", Findings: Group(c, []Advisory{a}, nil), InventoryDigest: "digest"}
	p := &profile.Profile{Manufacturer: profile.Manufacturer{Name: detect.String("Demo Manufacturer")}}
	for _, status := range []string{"affected", "not_affected", "fixed", "under_investigation"} {
		t.Run(status, func(t *testing.T) {
			p.Triage = []profile.Triage{{Advisory: detect.String("CVE-2022-31042"), Component: &c.PURL, Status: &status, Reason: detect.String("Reviewing use and preparing an update"), Justification: detect.String("vulnerable_code_not_in_execute_path"), DecidedOn: detect.String("2026-10-20")}}
			Apply(&r, p)
			b, e := VEX(r, p)
			if e != nil {
				t.Fatal(e)
			}
			v := ValidateVEX(t, b)
			statement := v["statements"].([]any)[0].(map[string]any)
			product := statement["products"].([]any)[0].(map[string]any)
			sub := product["subcomponents"].([]any)[0].(map[string]any)
			if product["@id"] != r.ProductPURL || sub["@id"] != c.PURL || statement["status_notes"] != *p.Triage[0].Reason || statement["status"] != status {
				t.Fatalf("wrong statement %s", b)
			}
			if status == "affected" && statement["action_statement"] != statement["status_notes"] {
				t.Fatal("lost action")
			}
			if status == "not_affected" && (statement["impact_statement"] != statement["status_notes"] || statement["justification"] == nil) {
				t.Fatal("lost impact")
			}
			again, _ := VEX(r, p)
			if string(again) != string(b) {
				t.Fatal("not content addressed")
			}
		})
	}
	root := t.TempDir()
	if e := Write(root, r, p); e != nil {
		t.Fatal(e)
	}
	p.Triage[0].Component = detect.String("pkg:composer/guzzlehttp/guzzle@7.5.0")
	Apply(&r, p)
	if r.Findings[0].Decision != nil || r.ScanID != "saved" || r.Complete {
		t.Fatal("reused history or changed provenance")
	}
	if e := Write(root, r, p); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(root, "cra/reports/vex.openvex.json")); !os.IsNotExist(e) {
		t.Fatal("obsolete VEX remained")
	}
}

func TestRecordedAcmeResponses(t *testing.T) {
	b, err := os.ReadFile("testdata/acme-responses.json")
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		Queries    map[string][]string
		Advisories map[string]Advisory
	}
	if err = json.Unmarshal(b, &saved); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev":
			b, _ := os.ReadFile("testdata/kev.json")
			w.Write(b)
		case "/v1/querybatch":
			var queries struct{ Queries []query }
			json.NewDecoder(r.Body).Decode(&queries)
			results := []any{}
			for _, q := range queries.Queries {
				eco := "npm"
				if q.Package.Ecosystem == "Packagist" {
					eco = "composer"
				}
				ids := saved.Queries[eco+":"+q.Package.Name+"@"+q.Version]
				entries := []any{}
				for _, id := range ids {
					entries = append(entries, map[string]string{"id": id})
				}
				results = append(results, map[string]any{"vulns": entries})
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		default:
			id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
			a, ok := saved.Advisories[id]
			if !ok {
				w.WriteHeader(404)
				return
			}
			json.NewEncoder(w).Encode(a)
		}
	}))
	defer server.Close()
	product, err := detect.Detect("../../testdata/wp-plugin/acme-booking")
	if err != nil {
		t.Fatal(err)
	}
	release := "../dist/acme-booking-2.3.1.zip"
	inv, err := inventory.BuildWithOptions("../../testdata/wp-plugin/acme-booking", product, inventory.Options{Release: &release})
	if err != nil {
		t.Fatal(err)
	}
	findings, reasons := (&Client{HTTP: server.Client(), OSV: server.URL, KEV: server.URL + "/kev"}).Lookup(context.Background(), inv, false)
	if len(reasons) != 0 {
		t.Fatal(reasons)
	}
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Component.Name] += len(f.Advisories)
	}
	for name, want := range map[string]int{"guzzlehttp/guzzle": 14, "moment": 2, "select2": 1, "jquery-validation": 4} {
		if counts[name] != want {
			t.Fatalf("%s got %d want %d", name, counts[name], want)
		}
	}
	for name, want := range map[string]string{"guzzlehttp/guzzle": "7.15.2", "moment": "2.29.4", "select2": "4.0.6", "jquery-validation": "1.20.0"} {
		for _, f := range findings {
			if f.Component.Name == name {
				if fix := SafeFix(f.Component, findings); fix != want {
					t.Fatalf("%s fix %q want %q", name, fix, want)
				}
				break
			}
		}
	}
	report := Report{Findings: findings, Complete: true, CoverageGaps: inv.CoverageGaps}
	md := string(Markdown(report))
	for _, required := range []string{"## Shipped", "## Not shipped", "vendor/guzzlehttp/guzzle", "assets/js/vendor/moment.min.js", "OSV.dev", "CISA KEV", "CC-BY 4.0", "Known exploited"} {
		if !strings.Contains(md, required) {
			t.Fatalf("missing %s", required)
		}
	}
}
