package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincentsch/conformline/internal/detect"
	"github.com/vincentsch/conformline/internal/docs"
	"github.com/vincentsch/conformline/internal/profile"
	"github.com/vincentsch/conformline/internal/vulns"
	"github.com/vincentsch/rungrad/testutil"
)

func TestInitScanAndDocumentFlow(t *testing.T) {
	var fail atomic.Bool
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/kev" {
			w.Write([]byte(`{"vulnerabilities":[]}`))
			return
		}
		var query struct{ Queries []json.RawMessage }
		if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
			t.Error(err)
		}
		results := make([]any, len(query.Queries))
		for i := range results {
			results[i] = map[string]any{"vulns": []any{}}
		}
		json.NewEncoder(w).Encode(map[string]any{"results": results})
	}))
	defer server.Close()
	client := &vulns.Client{HTTP: server.Client(), OSV: server.URL, KEV: server.URL + "/kev"}
	run := func(root string, want int, args ...string) []byte {
		t.Helper()
		var out, stderr bytes.Buffer
		args = append(args, "--dir", root, "--no-prompt", "--json")
		code := newApp(client).RunIO(args, strings.NewReader(""), &out, &stderr)
		if code != want {
			t.Fatalf("%v exit %d want %d: %s %s", args, code, want, out.String(), stderr.String())
		}
		if want == 0 || want == 11 {
			if !json.Valid(out.Bytes()) || stderr.Len() != 0 {
				t.Fatalf("not one JSON result: %s %s", out.String(), stderr.String())
			}
		}
		return out.Bytes()
	}
	for _, role := range []string{"manufacturer", "unknown", "not-in-scope", "open-source-steward", "absolute release"} {
		t.Run(role, func(t *testing.T) {
			absolute := role == "absolute release"
			if absolute {
				forceAbsolutePaths(t)
				role = "manufacturer"
			}
			base := t.TempDir()
			root := filepath.Join(base, "acme-booking")
			copyTree(t, "../../testdata/wp-plugin/acme-booking", root)
			copyTree(t, "../../testdata/wp-plugin/dist", filepath.Join(base, "dist"))
			answer := filepath.Join(base, "answers.yml")
			put(t, base, "answers.yml", "version: 1\nmanufacturer: {name: Example Maker}\nsecurity_contact: {email: null}\nrole: {answer: "+role+", decided_by: Maker}\nclassification: {categories: [i-3, ii-1, iv-3], decided_by: Reviewer}\n")
			release := "../dist/acme-booking-2.3.1.zip"
			if absolute {
				release = filepath.Join(base, "dist/acme-booking-2.3.1.zip")
			}
			b := run(root, 0, "init", "--answers", answer, "--release", release)
			var result initResult
			if err := json.Unmarshal(b, &result); err != nil {
				t.Fatal(err)
			}
			if !result.Scan.Complete || len(result.Status.Items) != 13 {
				t.Fatal(string(b))
			}
			p, err := profile.Load(filepath.Join(root, "cra.yml"))
			if err != nil {
				t.Fatal(err)
			}
			if p.Manufacturer.Name == nil || *p.Manufacturer.Name != "Example Maker" || p.Manufacturer.Address != nil || p.SecurityContact.Email != nil || p.Role.Answer != role {
				t.Fatalf("%+v", p)
			}
			if p.Product.Name == nil || *p.Product.Name != "Acme Booking" || result.Scan.Product.Version == nil || *result.Scan.Product.Version != "2.3.1" {
				t.Fatal("lost detection")
			}
			wantRelease := "../dist/acme-booking-2.3.1.zip"
			wantPattern := "../dist/acme-booking-{version}.zip"
			if absolute {
				wantRelease = filepath.ToSlash(filepath.Join(base, "dist/acme-booking-2.3.1.zip"))
				wantPattern = filepath.ToSlash(filepath.Join(base, "dist/acme-booking-{version}.zip"))
			}
			if result.Scan.Release == nil || *result.Scan.Release != wantRelease {
				t.Fatal("wrong initial inventory release", string(b))
			}
			if p.Product.Release == nil || *p.Product.Release != wantPattern {
				t.Fatalf("%+v", p.Product)
			}
			if p.Classification.Answer != "critical" || *p.Role.DecidedBy != "Maker" || *p.Classification.DecidedBy != "Reviewer" || *p.Role.DecidedOn != time.Now().Format("2006-01-02") {
				t.Fatalf("%+v %+v", p.Role, p.Classification)
			}
			b = run(root, 0, "scan")
			var scan Report
			json.Unmarshal(b, &scan)
			if scan.Release == nil || *scan.Release != wantRelease {
				t.Fatal(string(b))
			}
			var savedScan Report
			if err := json.Unmarshal([]byte(readFile(t, root, "cra/reports/inventory.json")), &savedScan); err != nil {
				t.Fatal(err)
			}
			if savedScan.Release == nil || *savedScan.Release != wantRelease {
				t.Fatal("wrong saved inventory release", savedScan.Release)
			}
			b = run(root, 0, "docs")
			var r docs.Result
			json.Unmarshal(b, &r)
			if len(r.Created) != 0 {
				t.Fatal(string(b))
			}
			if role == "not-in-scope" {
				if len(r.Existing) != 0 {
					t.Fatal(string(b))
				}
				for _, file := range docs.Files {
					if _, err := os.Stat(filepath.Join(root, file)); !os.IsNotExist(err) {
						t.Fatal(file, err)
					}
				}
			} else if len(r.Existing) != 9 {
				t.Fatal(string(b))
			}
			run(root, 1, "init")
		})
	}
	t.Run("failed lookup still creates documents", func(t *testing.T) {
		fail.Store(true)
		defer fail.Store(false)
		root := t.TempDir()
		copyTree(t, "../../testdata/wp-plugin/acme-booking", root)
		b := run(root, 11, "init")
		var result initResult
		json.Unmarshal(b, &result)
		if result.Scan.Complete || len(result.Scan.IncompleteReasons) == 0 || len(result.Documents.Created) != 9 {
			t.Fatal(string(b))
		}
	})
	t.Run("offline skips lookup", func(t *testing.T) {
		before := calls.Load()
		root := t.TempDir()
		copyTree(t, "../../testdata/wp-plugin/acme-booking", root)
		b := run(root, 11, "init", "--offline")
		if calls.Load() != before || !bytes.Contains(b, []byte(`"offline": true`)) {
			t.Fatal(string(b))
		}
	})
	t.Run("dry run skips git network and writes", func(t *testing.T) {
		root := t.TempDir()
		copyTree(t, "../../testdata/wp-plugin/acme-booking", root)
		fake := t.TempDir()
		marker := filepath.Join(fake, "called")
		put(t, fake, "git", "#!/bin/sh\nprintf called > '"+marker+"'\n")
		if err := os.Chmod(filepath.Join(fake, "git"), 0755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", fake+string(os.PathListSeparator)+os.Getenv("PATH"))
		before := calls.Load()
		b := run(root, 11, "init", "--dry-run")
		if calls.Load() != before {
			t.Fatal("dry run queried providers")
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatal("dry run invoked git")
		}
		for _, file := range []string{"cra.yml", "cra", "SECURITY.md"} {
			if _, err := os.Stat(filepath.Join(root, file)); !os.IsNotExist(err) {
				t.Fatal("dry run wrote", file)
			}
		}
		if !bytes.Contains(b, []byte(`"dry_run": true`)) {
			t.Fatal(string(b))
		}
	})
	t.Run("missing release stops before output files", func(t *testing.T) {
		root := t.TempDir()
		run(root, 2, "init", "--release", "missing.zip")
		if _, err := os.Stat(filepath.Join(root, "cra.yml")); !os.IsNotExist(err) {
			t.Fatal("created profile on invalid release")
		}
	})
}

func TestPartialAnswersThroughPromptGate(t *testing.T) {
	for _, prompt := range []bool{false, true} {
		t.Run(map[bool]string{true: "interactive", false: "no-prompt"}[prompt], func(t *testing.T) {
			root := t.TempDir()
			copyTree(t, "../../testdata/wp-plugin/acme-booking", root)
			answers := filepath.Join(t.TempDir(), "answers.yml")
			if err := os.WriteFile(answers, []byte("version: 1\nmanufacturer: {name: Example Maker}\nsecurity_contact: {email: null}\nrole: {answer: unknown}\n"), 0644); err != nil {
				t.Fatal(err)
			}
			// Five role fact choices, then the omitted maker address and remaining text fields.
			input := "1\n1\n1\n1\n1\nPostal address\n\nhttps://example.com/report\nunknown\n2031-10-31\n2.x\nWordPress updates\n3,20,26\nunknown\n"
			args := []string{"init", "--offline", "--answers", answers, "--dir", root}
			if !prompt {
				args = append(args, "--no-prompt")
			}
			r := testutil.RunWith(New(), testutil.Options{Stdin: strings.NewReader(input), TerminalSet: true, Terminal: true}, args...)
			if r.Exit != 11 {
				t.Fatalf("%+v", r)
			}
			p, err := profile.Load(filepath.Join(root, "cra.yml"))
			if err != nil {
				t.Fatal(err)
			}
			if *p.Manufacturer.Name != "Example Maker" || p.SecurityContact.Email != nil || p.Role.Answer != "unknown" {
				t.Fatalf("%+v", p)
			}
			combined := r.Stdout + r.Stderr
			for _, bad := range []string{"compliant product", "cra compliant", "certified", "guarantee", "ensures compliance", "cra-ready"} {
				if strings.Contains(strings.ToLower(combined), bad) {
					t.Fatal("forbidden output wording", bad)
				}
			}
			if strings.Contains(combined, "Email for vulnerability reports") || strings.Contains(combined, "Manufacturer name [") {
				t.Fatal("asked explicit answers", combined)
			}
			if prompt {
				if p.Manufacturer.Address == nil || *p.Manufacturer.Address != "Postal address" || p.Manufacturer.Website == nil || *p.Manufacturer.Website != "https://example.com" || p.Classification.Answer != "critical" {
					t.Fatalf("%+v\n%s", p, combined)
				}
				if strings.Count(combined, "Implementing Regulation (EU) 2025/2392") != 1 {
					t.Fatal("category note count", combined)
				}
			} else if p.Manufacturer.Address != nil || p.Classification.Answer != "unknown" {
				t.Fatalf("%+v", p)
			}
			if !strings.Contains(combined, "Acme Booking 2.3.1") {
				t.Fatal(combined)
			}
		})
	}
}

func TestGitIdentityReadOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The extensionless shell stub cannot replace Git on Windows")
	}
	root := t.TempDir()
	fake := t.TempDir()
	marker := filepath.Join(fake, "arguments")
	put(t, fake, "git", "#!/bin/sh\nprintf '%s\\n' \"$@\" > '"+marker+"'\nprintf 'Local Maker\\n'\n")
	if err := os.Chmod(filepath.Join(fake, "git"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fake+string(os.PathListSeparator)+os.Getenv("PATH"))
	r := testutil.RunWith(New(), testutil.Options{}, "init", "--offline", "--no-prompt", "--dir", root)
	if r.Exit != 11 {
		t.Fatalf("%+v", r)
	}
	b, err := os.ReadFile(marker)
	if err != nil || string(b) != "-C\n"+root+"\nconfig\nuser.name\n" {
		t.Fatalf("unexpected Git invocation: %q %v", b, err)
	}
	p, err := profile.Load(filepath.Join(root, "cra.yml"))
	if err != nil || p.Role.DecidedBy == nil || *p.Role.DecidedBy != "Local Maker" || p.Classification.DecidedBy == nil || *p.Classification.DecidedBy != "Local Maker" {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestDetectedInterviewDefaults(t *testing.T) {
	root := t.TempDir()
	copyTree(t, "../../testdata/wp-plugin/acme-booking", root)
	put(t, root, "SECURITY.md", "# Security\nReport privately to [security@example.com](mailto:security@example.com) or https://example.com/report.\n")
	product, err := detect.Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	p := contactDefaults(root, product)
	if p.Manufacturer.Name == nil || *p.Manufacturer.Name != "Acme Plugins GmbH" || p.Manufacturer.Website == nil || *p.Manufacturer.Website != "https://example.com" || p.SecurityContact.Email == nil || *p.SecurityContact.Email != "security@example.com" || p.SecurityContact.URL == nil || *p.SecurityContact.URL != "https://example.com/report" {
		t.Fatalf("%+v %+v", p.Manufacturer, p.SecurityContact)
	}
	other := t.TempDir()
	put(t, other, "composer.json", `{"name":"maker/library","homepage":"https://example.com/library","authors":[{"name":"Library Maker"}]}`)
	product, err = detect.Detect(other)
	if err != nil {
		t.Fatal(err)
	}
	p = contactDefaults(other, product)
	if p.Manufacturer.Name == nil || *p.Manufacturer.Name != "Library Maker" || p.Manufacturer.Website == nil || *p.Manufacturer.Website != "https://example.com/library" {
		t.Fatalf("%+v", p.Manufacturer)
	}
}

func TestInterviewReleaseCorrection(t *testing.T) {
	for _, tc := range []struct{ name, answer, want string }{
		{"literal", "releases/acme-booking-2.3.1.zip", "releases/acme-booking-{version}.zip"},
		{"pattern", "releases/acme-booking-{version}.zip", "releases/acme-booking-{version}.zip"},
		{"home", "~/Downloads/acme-booking-2.3.1.zip", "../home/Downloads/acme-booking-{version}.zip"},
		{"unknown", "unknown", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, "acme-booking")
			copyTree(t, "../../testdata/wp-plugin/acme-booking", root)
			zip, err := os.ReadFile("../../testdata/wp-plugin/dist/acme-booking-2.3.1.zip")
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{filepath.Join(root, "releases"), filepath.Join(base, "home/Downloads")} {
				if err := os.MkdirAll(path, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "acme-booking-2.3.1.zip"), zip, 0644); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("HOME", filepath.Join(base, "home"))
			t.Setenv("USERPROFILE", filepath.Join(base, "home"))
			answers := filepath.Join(base, "answers.yml")
			put(t, base, "answers.yml", "version: 1\nmanufacturer: null\nsecurity_contact: null\nsupport: null\nrole: null\nclassification: null\n")
			put(t, root, "invalid.zip", "This is not a ZIP.")
			input := "dist/acme-bookin-2.3.1.zip\ninvalid.zip\n" + tc.answer + "\n"
			r := testutil.RunWith(New(), testutil.Options{Stdin: strings.NewReader(input), TerminalSet: true, Terminal: true}, "init", "--offline", "--answers", answers, "--dir", root)
			if r.Exit != 11 {
				t.Fatalf("%+v", r)
			}
			if strings.Count(r.Stderr, "Release ZIP or folder, relative to --dir") != 3 ||
				!strings.Contains(r.Stderr, "missing or unreadable") || !strings.Contains(r.Stderr, "not a readable ZIP") {
				t.Fatal(r.Stderr)
			}
			p, err := profile.Load(filepath.Join(root, "cra.yml"))
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if p.Product.Release != nil {
					t.Fatal(*p.Product.Release)
				}
			} else if p.Product.Release == nil || *p.Product.Release != tc.want {
				t.Fatalf("release: %v; want %s", p.Product.Release, tc.want)
			}
			for _, file := range append(append([]string{}, docs.Files...), "cra/README.md", "cra/reports/inventory.json") {
				if _, err := os.Stat(filepath.Join(root, file)); err != nil {
					t.Fatal(file, err)
				}
			}
			if !strings.Contains(r.Stdout, "Full status: cra/reports/status.html") {
				t.Fatal(r.Stdout)
			}
		})
	}
}

func TestRoleHintDistinguishesCompleteAnswers(t *testing.T) {
	for _, tc := range []struct{ sold, want string }{
		{"false", "These answers do not suggest a typical role"},
		{"null", "The answers are incomplete"},
	} {
		t.Run(tc.sold, func(t *testing.T) {
			root := t.TempDir()
			answers := filepath.Join(t.TempDir(), "answers.yml")
			text := "version: 1\nrole:\n  answers: {sold: " + tc.sold + ", paid_edition: false, paid_support: false, donations_only: false, hosted_only: false}\nmanufacturer: null\nsecurity_contact: null\nsupport: null\nclassification: null\nproduct: {release: null}\n"
			if err := os.WriteFile(answers, []byte(text), 0644); err != nil {
				t.Fatal(err)
			}
			r := testutil.RunWith(New(), testutil.Options{Stdin: strings.NewReader("1\n"), TerminalSet: true, Terminal: true}, "init", "--offline", "--answers", answers, "--dir", root)
			if r.Exit != 11 || !strings.Contains(r.Stderr, tc.want) {
				t.Fatalf("%+v", r)
			}
			if tc.sold == "false" && strings.Contains(r.Stderr, "answers are incomplete") {
				t.Fatal(r.Stderr)
			}
			p, err := profile.Load(filepath.Join(root, "cra.yml"))
			if err != nil || p.Role.Answer != "unknown" {
				t.Fatal(p, err)
			}
		})
	}
}
