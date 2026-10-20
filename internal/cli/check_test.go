package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincentsch/conformline/internal/detect"
	"github.com/vincentsch/conformline/internal/profile"
	"github.com/vincentsch/conformline/internal/status"
	"github.com/vincentsch/conformline/internal/vulns"
)

func checkClient(t *testing.T) *vulns.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/kev" {
			w.Write([]byte(`{"vulnerabilities":[]}`))
			return
		}
		var query struct{ Queries []json.RawMessage }
		json.NewDecoder(r.Body).Decode(&query)
		results := make([]any, len(query.Queries))
		for i := range results {
			results[i] = map[string]any{"vulns": []any{}}
		}
		json.NewEncoder(w).Encode(map[string]any{"results": results})
	}))
	t.Cleanup(server.Close)
	return &vulns.Client{HTTP: server.Client(), OSV: server.URL, KEV: server.URL + "/kev"}
}
func runCheckCLI(t *testing.T, client *vulns.Client, root string, want int, args ...string) []byte {
	t.Helper()
	var out, stderr bytes.Buffer
	args = append(args, "--dir", root, "--no-prompt", "--json")
	code := newApp(client).RunIO(args, strings.NewReader(""), &out, &stderr)
	if code != want {
		t.Fatalf("%v exit %d want %d: %s %s", args, code, want, out.String(), stderr.String())
	}
	if want == 0 || want == 10 || want == 11 {
		if !json.Valid(out.Bytes()) || stderr.Len() != 0 {
			t.Fatalf("not one JSON result: %s %s", out.String(), stderr.String())
		}
	}
	return out.Bytes()
}
func TestCheckRequiresProfileAndDryRun(t *testing.T) {
	root := t.TempDir()
	client := checkClient(t)
	var out, stderr bytes.Buffer
	code := newApp(client).RunIO([]string{"check", "--dir", root}, strings.NewReader(""), &out, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "Run `conformline init` first") {
		t.Fatal(code, stderr.String())
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 {
		t.Fatal("wrote without profile")
	}
	put(t, root, "cra.yml", "version: 1\nrole: {answer: unknown}\n")
	summary := filepath.Join(t.TempDir(), "summary.md")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	runCheckCLI(t, client, root, 11, "check", "--ci", "--dry-run")
	if _, e := os.Stat(summary); !os.IsNotExist(e) {
		t.Fatal("dry run wrote summary")
	}
	if _, e := os.Stat(filepath.Join(root, "cra")); !os.IsNotExist(e) {
		t.Fatal("dry run wrote reports")
	}
}
func TestCheckReleaseReplayAndCloneTimestamps(t *testing.T) {
	client := checkClient(t)
	base := t.TempDir()
	root := filepath.Join(base, "acme-booking")
	copyTree(t, "../../testdata/wp-plugin/acme-booking", root)
	copyTree(t, "../../testdata/wp-plugin/dist", filepath.Join(base, "dist"))
	put(t, root, "cra.yml", "version: 1\nrole: {answer: not-in-scope}\n")
	runCheckCLI(t, client, root, 0, "scan", "--release", "../dist/acme-booking-2.3.1.zip")
	b := runCheckCLI(t, client, root, 0, "check", "--strict")
	var result status.Result
	json.Unmarshal(b, &result)
	if !result.ScanComplete || len(result.ScanIssues) > 0 {
		t.Fatal(string(b))
	}
	// Clone-like mtimes deliberately invert the order of source and report writes.
	filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
		if e == nil && !d.IsDir() {
			stamp := time.Now().Add(48 * time.Hour)
			if strings.Contains(path, "reports") {
				stamp = stamp.Add(-96 * time.Hour)
			}
			os.Chtimes(path, stamp, stamp)
		}
		return e
	})
	cloneBase := t.TempDir()
	clone := filepath.Join(cloneBase, "acme-booking")
	copyTree(t, root, clone)
	copyTree(t, filepath.Join(base, "dist"), filepath.Join(cloneBase, "dist"))
	runCheckCLI(t, client, clone, 0, "check", "--strict")
	p, e := profile.Load(filepath.Join(root, "cra.yml"))
	if e != nil {
		t.Fatal(e)
	}
	p.Triage = []profile.Triage{{Advisory: detect.String("old-advisory"), Component: detect.String("pkg:npm/moment@1.0.0"), Status: detect.String("fixed"), Reason: detect.String("Historical decision"), DecidedOn: detect.String("2026-10-20")}}
	if e = p.Save(filepath.Join(root, "cra.yml")); e != nil {
		t.Fatal(e)
	}
	runCheckCLI(t, client, root, 0, "check")
	os.Remove(filepath.Join(base, "dist/acme-booking-2.3.1.zip"))
	b = runCheckCLI(t, client, root, 11, "check")
	if !strings.Contains(string(b), "recorded release ../dist/") {
		t.Fatal(string(b))
	}
}
func TestCheckCISummaryAndIndex(t *testing.T) {
	root := t.TempDir()
	client := checkClient(t)
	put(t, root, "package.json", `{"name":"sample","version":"1.0.0"}`)
	put(t, root, "cra.yml", "version: 1\nrole: {answer: manufacturer}\n")
	runCheckCLI(t, client, root, 0, "scan")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	runCheckCLI(t, client, root, 0, "check", "--ci")
	summary := filepath.Join(t.TempDir(), "summary.md")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	b := runCheckCLI(t, client, root, 0, "check", "--ci")
	var r status.Result
	json.Unmarshal(b, &r)
	report, _ := os.ReadFile(filepath.Join(root, "cra/reports/status.md"))
	summaryBytes, _ := os.ReadFile(summary)
	if string(summaryBytes) != string(report)+"\n" {
		t.Fatal("summary differs from report")
	}
	index, _ := os.ReadFile(filepath.Join(root, "cra/README.md"))
	if !strings.Contains(string(index), "reports/status.html") {
		t.Fatal("missing report link")
	}
	runCheckCLI(t, client, root, 10, "check", "--strict")
}
func TestUnknownProductVersionAndVersionReview(t *testing.T) {
	client := checkClient(t)
	for _, scenario := range []string{"unknown", "override", "stable tag"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			put(t, root, "cra.yml", "version: 1\nrole: {answer: not-in-scope}\n")
			if scenario == "stable tag" {
				put(t, root, "plugin.php", "<?php\n/*\nPlugin Name: Sample\nVersion: 1.0.0\n*/")
				put(t, root, "readme.txt", "Stable tag: 2.0.0\n")
			} else {
				body := `{"name":"sample"}`
				if scenario == "override" {
					body = `{"name":"sample","version":"1.0.0"}`
					put(t, root, "cra.yml", "version: 1\nproduct: {version: 2.0.0}\nrole: {answer: not-in-scope}\n")
				}
				put(t, root, "package.json", body)
			}
			runCheckCLI(t, client, root, 0, "scan")
			b := runCheckCLI(t, client, root, 0, "check")
			var r status.Result
			json.Unmarshal(b, &r)
			item := r.Items[4]
			if item.State != status.Review {
				t.Fatal(item)
			}
			for _, format := range []string{string(b), readFile(t, root, "cra/reports/status.md"), readFile(t, root, "cra/reports/status.html")} {
				if scenario == "unknown" {
					if !strings.Contains(format, "product.version") {
						t.Fatal("missing version action")
					}
				} else {
					for _, version := range []string{"1.0.0", "2.0.0"} {
						if !strings.Contains(format, version) {
							t.Fatal("missing version", version)
						}
					}
				}
			}
			var out, stderr bytes.Buffer
			if code := newApp(client).RunIO([]string{"check", "--dir", root}, strings.NewReader(""), &out, &stderr); code != 0 {
				t.Fatal(code)
			}
			if scenario != "unknown" && (!strings.Contains(out.String(), "1.0.0") || !strings.Contains(out.String(), "2.0.0")) {
				t.Fatal(out.String())
			}
		})
	}
}
func readFile(t *testing.T, root, path string) string {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(root, path))
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}

func TestFrozenLookupStatusReports(t *testing.T) {
	var specs []struct {
		Name, Ecosystem, Version, Fixed, Severity string
		Groups                                    int
	}
	b, e := os.ReadFile("../vulns/testdata/status-findings.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &specs); e != nil {
		t.Fatal(e)
	}
	byID := map[string]vulns.Advisory{}
	byName := map[string][]map[string]string{}
	for _, s := range specs {
		for i := 0; i < s.Groups; i++ {
			id := fmt.Sprintf("GHSA-fixture-%s-%02d", strings.ReplaceAll(s.Name, "/", "-"), i)
			a := vulns.Advisory{ID: id, Summary: "Update <dependency> & review", Affected: []vulns.Affected{{Package: vulns.Package{Name: s.Name, Ecosystem: s.Ecosystem}, Ranges: []vulns.Range{{Type: "ECOSYSTEM", Events: []vulns.Event{{Introduced: "0"}, {Fixed: s.Fixed}}}}}}}
			a.DatabaseSpecific.Severity = s.Severity
			byID[id] = a
			byName[s.Name] = append(byName[s.Name], map[string]string{"id": id})
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/kev":
			w.Write([]byte(`{"vulnerabilities":[]}`))
		case r.URL.Path == "/v1/querybatch":
			var q struct {
				Queries []struct{ Package struct{ Name string } }
			}
			json.NewDecoder(r.Body).Decode(&q)
			results := []any{}
			for _, entry := range q.Queries {
				ids := byName[entry.Package.Name]
				if ids == nil {
					ids = []map[string]string{}
				}
				results = append(results, map[string]any{"vulns": ids})
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		default:
			a, ok := byID[strings.TrimPrefix(r.URL.Path, "/v1/vulns/")]
			if !ok {
				w.WriteHeader(404)
				return
			}
			json.NewEncoder(w).Encode(a)
		}
	}))
	defer server.Close()
	client := &vulns.Client{HTTP: server.Client(), OSV: server.URL, KEV: server.URL + "/kev"}
	base := t.TempDir()
	root := filepath.Join(base, "acme-booking")
	copyTree(t, "../../testdata/wp-plugin/acme-booking", root)
	copyTree(t, "../../testdata/wp-plugin/dist", filepath.Join(base, "dist"))
	put(t, base, "answers.yml", "version: 1\nrole: {answer: manufacturer}\nclassification: {answer: default}\n")
	b = runCheckCLI(t, client, root, 0, "init", "--answers", filepath.Join(base, "answers.yml"), "--release", "../dist/acme-booking-2.3.1.zip")
	var initialized initResult
	json.Unmarshal(b, &initialized)
	if initialized.Status.ExitCode != 0 {
		t.Fatal(string(b))
	}
	b = runCheckCLI(t, client, root, 0, "check")
	var result status.Result
	json.Unmarshal(b, &result)
	for i, name := range []string{"guzzlehttp/guzzle", "jQuery Validation", "moment.js", "guzzlehttp/psr7", "Select2"} {
		if len(result.Next) != 5 || !strings.Contains(result.Next[i], name) {
			t.Fatal(result.Next)
		}
	}
	if len(result.Findings) != 46 {
		t.Fatal("expected frozen groups including non-shipped", len(result.Findings))
	}
	if !strings.Contains(readFile(t, root, "cra/reports/status.html"), "&lt;dependency&gt;") {
		t.Fatal("unescaped advisory")
	}
	if path := os.Getenv("CONFORMLINE_ACCEPTANCE_ROOT"); path != "" {
		copyTree(t, root, filepath.Join(path, "acme-booking"))
		copyTree(t, filepath.Join(base, "dist"), filepath.Join(path, "dist"))
	}
	if path := os.Getenv("CONFORMLINE_LOOKUP_FIXTURE"); path != "" {
		if e := status.Write(path, result); e != nil {
			t.Fatal(e)
		}
	}
}

func TestPreparationIndexAcrossCommands(t *testing.T) {
	client := checkClient(t)
	for _, role := range []string{"manufacturer", "not-in-scope", "unknown", "open-source-steward"} {
		t.Run(role, func(t *testing.T) {
			root := t.TempDir()
			put(t, root, "package.json", `{"name":"sample","version":"1.0.0"}`)
			answers := filepath.Join(t.TempDir(), "answers.yml")
			put(t, filepath.Dir(answers), filepath.Base(answers), "version: 1\nrole: {answer: "+role+"}\nclassification: {answer: default}\n")
			b := runCheckCLI(t, client, root, 0, "init", "--answers", answers)
			var initialized initResult
			if e := json.Unmarshal(b, &initialized); e != nil {
				t.Fatal(e)
			}
			verifyIndex := func(next []string) string {
				t.Helper()
				index := readFile(t, root, "cra/README.md")
				normalized := strings.Join(strings.Fields(index), " ")
				for _, text := range []string{"# CRA preparation documents", "## Next steps", "reports/status.md", "reports/status.html", "Lookups send package names, versions and advisory ids to OSV.dev and download CISA KEV.", "no presumption of conformity is available", "C(2026) 5252", "non-binding", "Conformline helps prepare evidence and does not give legal advice.", "Requirement: Art. 13, Art. 14; Annex I, II, V and VII."} {
					if !strings.Contains(normalized, text) {
						t.Fatalf("index missing %q: %s", text, index)
					}
				}
				for _, action := range next {
					if !strings.Contains(html.UnescapeString(index), action) {
						t.Fatalf("index missing evaluated action %q", action)
					}
				}
				if role == "not-in-scope" {
					if !strings.Contains(index, "Manufacturer documents are skipped") || strings.Contains(index, "## Publish the reporting contact") || strings.Contains(index, "](security.txt)") || strings.Contains(index, "missing (missing)") {
						t.Fatal(index)
					}
				} else {
					for _, text := range []string{"## Publish the reporting contact", "/.well-known/security.txt", "Set Canonical to the published URL and refresh Expires before it passes.", "Publish the disclosure policy and set its public URL in cra.yml."} {
						if !strings.Contains(normalized, text) {
							t.Fatal("missing deployment instructions", text)
						}
					}
				}
				if role == "unknown" && !strings.Contains(index, "Your role needs your decision first.") {
					t.Fatal(index)
				}
				if role == "open-source-steward" && !strings.Contains(index, "does not assess steward obligations under Art. 24.") {
					t.Fatal(index)
				}
				return index
			}
			verifyIndex(initialized.Status.Next)
			for _, command := range []string{"docs", "check", "docs", "check"} {
				b = runCheckCLI(t, client, root, 0, command)
				var current status.Result
				check := runCheckCLI(t, client, root, 0, "check", "--dry-run")
				if e := json.Unmarshal(check, &current); e != nil {
					t.Fatal(e)
				}
				verifyIndex(current.Next)
			}
			if role == "not-in-scope" {
				for _, d := range initialized.Status.Documents {
					if d.State != status.NA || d.Status != "not applicable" {
						t.Fatal(d)
					}
				}
				for _, file := range []string{"cra/reports/status.md", "cra/reports/status.html"} {
					report := html.UnescapeString(readFile(t, root, file))
					if strings.Contains(report, "missing (missing)") || !strings.Contains(report, "not applicable") {
						t.Fatal(report)
					}
				}
			}
		})
	}
}
