package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincentsch/conformline/internal/profile"
	"github.com/vincentsch/conformline/internal/vulns"
	"github.com/vincentsch/rungrad/testutil"
)

func TestDemoCompletesWithOfflineAndFailedLookups(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(503) }))
	defer server.Close()
	client := &vulns.Client{HTTP: server.Client(), OSV: server.URL, KEV: server.URL + "/kev"}
	fake := t.TempDir()
	marker := filepath.Join(fake, "called")
	put(t, fake, "git", "#!/bin/sh\nprintf called > '"+marker+"'\n")
	if err := os.Chmod(filepath.Join(fake, "git"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fake+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, mode := range []string{"offline", "failed", "preview", "absolute offline", "absolute failed", "absolute preview"} {
		t.Run(mode, func(t *testing.T) {
			absolute := strings.HasPrefix(mode, "absolute ")
			if absolute {
				forceAbsolutePaths(t)
				mode = strings.TrimPrefix(mode, "absolute ")
			}
			out := filepath.Join(t.TempDir(), "demo with spaces")
			args := []string{"demo", "--out", out, "--json"}
			if mode == "offline" {
				args = append(args, "--offline")
			}
			if mode == "preview" {
				args = append(args, "--dry-run")
			}
			before := calls.Load()
			result := testutil.RunWith(newApp(client), testutil.Options{Terminal: true, TerminalSet: true}, args...)
			expected := 11
			if mode == "preview" {
				expected = 0
			}
			if result.Exit != expected || result.Stderr != "" || !json.Valid([]byte(result.Stdout)) {
				t.Fatalf("%+v", result)
			}
			var r demoResult
			if err := json.Unmarshal([]byte(result.Stdout), &r); err != nil {
				t.Fatal(err)
			}

			root := filepath.Join(out, "acme-booking")
			wantDirectory := filepath.ToSlash(root)
			if !absolute {
				cwd, err := os.Getwd()
				if err != nil {
					t.Fatal(err)
				}
				wantDirectory = expectedReleasePath(t, cwd, root)
			}
			if r.Directory != wantDirectory || r.StatusPath != wantDirectory+"/cra/reports/status.html" || r.DocumentsPath != wantDirectory+"/cra" || r.SBOMPath != wantDirectory+"/cra/reports/sbom.cdx.json" {
				t.Fatalf("incorrect output paths: %+v", r)
			}
			if mode == "failed" && !strings.Contains(r.LookupHint, "--offline") {
				t.Fatal("missing offline recovery hint")
			}
			if mode != "failed" && calls.Load() != before {
				t.Fatal("unexpected network call")
			}
			if mode == "preview" {
				if _, err := os.Stat(out); !os.IsNotExist(err) {
					t.Fatal("preview wrote files")
				}
				return
			}
			for _, path := range []string{r.StatusPath, r.DocumentsPath, r.SBOMPath} {
				if _, err := os.Stat(filepath.FromSlash(path)); err != nil {
					t.Fatal(path, err)
				}
			}
			p, err := profile.Load(filepath.Join(root, "cra.yml"))
			if err != nil {
				t.Fatal(err)
			}
			if *p.Manufacturer.Name != "Acme Plugins GmbH (demo)" || *p.Role.DecidedBy != "Demo User" || *p.Classification.DecidedBy != "Demo User" || p.Role.Answer != "manufacturer" || p.Classification.Answer != "default" || p.Manufacturer.Address != nil || *p.Support.End != time.Now().AddDate(5, 0, 0).Format("2006-01-02") {
				t.Fatalf("%+v", p)
			}
			if r.Init.Scan.Complete || len(r.Init.Scan.IncompleteReasons) == 0 || len(r.Commands) != 3 || !strings.HasPrefix(r.Commands[0], "conformline scan ") || !strings.Contains(r.Commands[1], `--title "Demo vulnerability"`) || strings.Contains(r.Commands[1], "--confirm") || strings.Contains(r.Commands[1], "--aware") {
				t.Fatal(result.Stdout)
			}
			for _, command := range r.Commands {
				if !strings.Contains(command, "--dir '"+r.Directory+"'") {
					t.Fatal(command)
				}
			}
			for _, file := range []string{"cra/reports/status.html", "cra/reports/sbom.cdx.json", "cra/README.md", "../dist/acme-booking-2.3.1.zip"} {
				if _, err := os.Stat(filepath.Join(root, file)); err != nil {
					t.Fatal(file, err)
				}
			}
			// Refusal happens before any modification, including a hidden destination entry.
			put(t, out, ".keep", "unchanged")
			again := testutil.RunWith(newApp(client), testutil.Options{}, "demo", "--offline", "--out", out)
			if again.Exit != 1 || !strings.Contains(again.Stderr, "--out is not empty") {
				t.Fatalf("%+v", again)
			}
			b, _ := os.ReadFile(filepath.Join(out, ".keep"))
			if string(b) != "unchanged" {
				t.Fatal("modified destination")
			}
		})
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("demo invoked git")
	}
}

func TestDemoOnlineAndTriageCommand(t *testing.T) {
	id := "GHSA-f2wf-25xc-69c9"
	var exploited atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev":
			if exploited.Load() {
				ioJSON(w, `{"vulnerabilities":[{"cveID":"CVE-2022-31042"}]}`)
			} else {
				ioJSON(w, `{"vulnerabilities":[]}`)
			}
		case "/v1/querybatch":
			var q struct {
				Queries []struct{ Package struct{ Name string } }
			}
			json.NewDecoder(r.Body).Decode(&q)
			results := []any{}
			for _, entry := range q.Queries {
				ids := []any{}
				if entry.Package.Name == "guzzlehttp/guzzle" {
					ids = append(ids, map[string]string{"id": id})
				}
				results = append(results, map[string]any{"vulns": ids})
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		default:
			b, err := os.ReadFile("../vulns/testdata/" + id + ".json")
			if err != nil {
				t.Error(err)
			}
			w.Write(b)
		}
	}))
	defer server.Close()
	client := &vulns.Client{HTTP: server.Client(), OSV: server.URL, KEV: server.URL + "/kev"}
	out := filepath.Join(t.TempDir(), "demo")
	r := testutil.RunWith(newApp(client), testutil.Options{}, "demo", "--json", "--out", out)
	if r.Exit != 0 || r.Stderr != "" {
		t.Fatalf("%+v", r)
	}
	var result demoResult
	if err := json.Unmarshal([]byte(r.Stdout), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Init.Scan.Complete || !strings.Contains(result.Commands[0], id) || !strings.Contains(result.Commands[0], "--component 'pkg:composer/guzzlehttp/guzzle@7.4.0'") {
		t.Fatal(r.Stdout)
	}
	exploited.Store(true)
	policy := testutil.RunWith(newApp(client), testutil.Options{}, "demo", "--json", "--out", filepath.Join(t.TempDir(), "policy"))
	if policy.Exit != 10 || !strings.Contains(policy.Stdout, `"commands"`) {
		t.Fatalf("%+v", policy)
	}
	exploited.Store(false)

	root := filepath.Join(out, "acme-booking")
	data, _ := os.ReadFile(filepath.Join(root, "cra/reports/vulnerabilities.json"))
	var report vulns.Report
	json.Unmarshal(data, &report)
	// One advisory can affect multiple installed versions; the printed component resolves it.
	duplicate := report.Findings[0]
	duplicate.Component.PURL = "pkg:composer/guzzlehttp/guzzle@7.3.0"
	report.Findings = append(report.Findings, duplicate)
	p, err := profile.Load(filepath.Join(root, "cra.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err = vulns.Write(root, report, p); err != nil {
		t.Fatal(err)
	}
	triage := testutil.RunWith(newApp(client), testutil.Options{}, "triage", id, "--status", "under_investigation", "--reason", "Demo exercise only", "--component", report.Findings[0].Component.PURL, "--dir", root)
	if triage.Exit != 0 {
		t.Fatalf("%+v", triage)
	}
	p, err = profile.Load(filepath.Join(root, "cra.yml"))
	if err != nil || len(p.Triage) != 1 || *p.Triage[0].Reason != "Demo exercise only" || *p.Triage[0].Status != "under_investigation" {
		t.Fatalf("%+v %v", p, err)
	}
}

func ioJSON(w http.ResponseWriter, s string) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(s))
}

func TestDemoHumanOutputAndLegalWording(t *testing.T) {

	for _, absolute := range []bool{false, true} {
		t.Run(map[bool]string{false: "native paths", true: "absolute paths"}[absolute], func(t *testing.T) {
			if absolute {
				forceAbsolutePaths(t)
			}
			out := filepath.Join(t.TempDir(), "demo with spaces")
			result := testutil.RunWith(New(), testutil.Options{}, "demo", "--offline", "--out", out)
			if result.Exit != 11 {
				t.Fatalf("%+v", result)
			}

			root := filepath.Join(out, "acme-booking")
			cwd, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			display := expectedReleasePath(t, cwd, root)
			if absolute {
				display = filepath.ToSlash(root)
			}
			for _, text := range []string{"Open status: " + display + "/cra/reports/status.html", "Draft documents: " + display + "/cra/", "SBOM: " + display + "/cra/reports/sbom.cdx.json"} {
				if !strings.Contains(result.Stdout, text) {
					t.Fatal("missing path", text, result.Stdout)
				}
			}
			if strings.Count(result.Stdout, "--dir '"+display+"'") != 3 {
				t.Fatal("next commands lost quoted directory", result.Stdout)
			}
			combined := result.Stdout + result.Stderr
			for _, want := range []string{"Found", "moment.js 2.24.0", "Select2 4.0.5", "jQuery Validation 1.19.1", "Scan incomplete:", "Open status:", "Draft documents:", "SBOM:", "Try next:"} {
				if !strings.Contains(combined, want) {
					t.Errorf("missing %s: %s", want, combined)
				}
			}
			for _, bad := range []string{"compliant product", "cra compliant", "certified", "guarantee", "ensures compliance", "cra-ready"} {
				if bytes.Contains(bytes.ToLower([]byte(combined)), []byte(bad)) {
					t.Fatal(bad)
				}
			}

		})
	}
}
