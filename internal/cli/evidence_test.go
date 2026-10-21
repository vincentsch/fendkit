package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vincentsch/fendkit/internal/profile"
	"github.com/vincentsch/fendkit/internal/status"
	"github.com/vincentsch/fendkit/internal/vulns"
)

func TestReleaseConfigurationFreshness(t *testing.T) {
	client := checkClient(t)
	root := t.TempDir()
	put(t, root, "plugin.php", "<?php\n/* Plugin Name: Example\nVersion: 1.0\n*/")
	for _, dir := range []string{"a", "b"} {
		os.MkdirAll(filepath.Join(root, dir), 0755)
		put(t, root, dir+"/plugin.php", "<?php\n/* Plugin Name: Example\nVersion: 1.0\n*/")
	}
	put(t, root, "cra.yml", "version: 1\nrole: {answer: not-in-scope}\nproduct: {release: a}\n")
	runCheckCLI(t, client, root, 0, "scan", "--release", "a")
	runCheckCLI(t, client, root, 0, "check")
	put(t, root, "cra.yml", "version: 1\nrole: {answer: not-in-scope}\nproduct: {release: b}\n")
	b := runCheckCLI(t, client, root, 11, "check")
	var r status.Result
	json.Unmarshal(b, &r)
	if r.ScanState != "stale" || !strings.Contains(strings.Join(r.ScanIssues, " "), "release configuration changed") {
		t.Fatal(string(b))
	}
	runCheckCLI(t, client, root, 0, "docs")
	index, _ := os.ReadFile(filepath.Join(root, "cra/README.md"))
	if !strings.Contains(string(index), "release configuration changed") {
		t.Fatal(string(index))
	}
}
func TestInitPreservesDecisionDates(t *testing.T) {
	client := checkClient(t)
	root := t.TempDir()
	answers := filepath.Join(t.TempDir(), "answers.yml")
	put(t, root, "package.json", `{"name":"example","version":"1.0"}`)
	os.WriteFile(answers, []byte("version: 1\nrole: {answer: manufacturer, decided_on: 2026-10-01}\nclassification: {answer: default, decided_on: 2026-10-02}\n"), 0600)
	runCheckCLI(t, client, root, 0, "init", "--answers", answers)
	p, err := profile.Load(filepath.Join(root, "cra.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Role.DecidedOn == nil || *p.Role.DecidedOn != "2026-10-01" || p.Classification.DecidedOn == nil || *p.Classification.DecidedOn != "2026-10-02" {
		t.Fatalf("dates replaced: %+v %+v", p.Role, p.Classification)
	}
}

func TestReleaseRecoveryBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		saved, override, changed string
		legacy, absolute         bool
		want                     string
	}{
		{name: "unchanged explicit override", saved: "a", override: "b", want: "b"},
		{name: "changed setting with override", saved: "a", override: "a", changed: "b", want: "b"},
		{name: "flag only", override: "b", want: "b"},
		{name: "legacy configured", saved: "b", override: "a", legacy: true, want: "b"},
		{name: "legacy flag only", override: "a", legacy: true, want: "a"},
		{name: "legacy repository only", legacy: true},
		{name: "different volume override", override: "b", absolute: true, want: "b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := checkClient(t)
			root := t.TempDir()
			if tc.absolute {
				forceAbsolutePaths(t)
			}
			for _, dir := range []string{"a", "b"} {
				os.MkdirAll(filepath.Join(root, dir), 0755)
				put(t, root, dir+"/plugin.php", "<?php\n/* Plugin Name: Example\nVersion: 1.0\n*/")
			}
			put(t, root, "plugin.php", "<?php\n/* Plugin Name: Example\nVersion: 1.0\n*/")
			profileText := func(setting string) string {
				s := "version: 1\nrole: {answer: not-in-scope}\n"
				if setting != "" {
					s += "product: {release: " + setting + "}\n"
				}
				return s
			}
			put(t, root, "cra.yml", profileText(tc.saved))
			args := []string{"scan"}
			if tc.override != "" {
				args = append(args, "--release", tc.override)
			}
			runCheckCLI(t, client, root, 0, args...)
			if tc.legacy {
				var inv map[string]any
				json.Unmarshal([]byte(readFile(t, root, "cra/reports/inventory.json")), &inv)
				delete(inv, "release_configuration")
				b, _ := json.Marshal(inv)
				put(t, root, "cra/reports/inventory.json", string(b))
			}
			if tc.changed != "" {
				put(t, root, "cra.yml", profileText(tc.changed))
			}
			wantExit := 0
			if tc.legacy || tc.changed != "" {
				wantExit = 11
			}
			runCheckCLI(t, client, root, 0, "docs")
			var result status.Result
			json.Unmarshal(runCheckCLI(t, client, root, wantExit, "check"), &result)
			if result.ScanComplete != (wantExit == 0) {
				t.Fatal(result)
			}
			index := readFile(t, root, "cra/README.md")
			if wantExit == 0 {
				return
			}
			if !strings.Contains(index, "stale (") {
				t.Fatal(index)
			}
			if tc.changed != "" && !strings.Contains(index, "release configuration changed") {
				t.Fatal(index)
			}
			if tc.legacy && !strings.Contains(strings.Join(result.ScanIssues, " "), "provenance is unavailable") {
				t.Fatal(result.ScanIssues)
			}
			// Execute exactly the generated scan arguments through the same command dispatcher.
			recovery := strings.Join(result.Next, "\n")
			pattern := regexp.MustCompile(`fendkit scan(?: --release '([^']*)')?`)
			match := pattern.FindStringSubmatch(recovery)
			if match == nil {
				t.Fatal("no recovery", recovery)
			}
			args = []string{"scan"}
			if match[1] != "" {
				args = append(args, "--release", match[1])
			}
			beforeProfile := readFile(t, root, "cra.yml")
			runCheckCLI(t, client, root, 0, args...)
			runCheckCLI(t, client, root, 0, "docs")
			runCheckCLI(t, client, root, 0, "check")
			var after Report
			json.Unmarshal([]byte(readFile(t, root, "cra/reports/inventory.json")), &after)
			want := tc.want
			if want != "" && tc.absolute {
				want = filepath.ToSlash(filepath.Join(root, want))
			}
			if want == "" {
				if after.Release != nil {
					t.Fatal(after.Release)
				}
			} else if after.Release == nil || *after.Release != want {
				t.Fatalf("wrong recovered boundary: %v want %s", after.Release, want)
			}
			if beforeProfile != readFile(t, root, "cra.yml") {
				t.Fatal("recovery rewrote profile")
			}
		})
	}
}

func TestInitClassificationMatrix(t *testing.T) {
	for _, tc := range []struct {
		input, want string
		invalid     bool
	}{
		{input: "categories: [ii-1]", want: "important-class-ii"}, {input: "categories: []", want: "default"},
		{input: "answer: important-class-ii, categories: [ii-1]", want: "important-class-ii"},
		{input: "answer: default, categories: []", want: "default"},
		{input: "answer: default, categories: [ii-1]", invalid: true},
		{input: "answer: unknown, categories: null", want: "unknown"}, {input: "answer: unknown", want: "unknown"},
		{input: "answer: null, categories: null", want: "unknown"}, {input: "answer: unknown, categories: []", invalid: true},
		{input: "answer: unknown, categories: [ii-1]", invalid: true}, {input: "answer: null, categories: []", invalid: true},
		{input: "answer: critical", want: "critical"}, {input: "answer: important-class-ii, categories: null", want: "important-class-ii"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			root := t.TempDir()
			put(t, root, "package.json", `{"name":"example","version":"1.0"}`)
			answers := filepath.Join(t.TempDir(), "answers.yml")
			os.WriteFile(answers, []byte("version: 1\nclassification: {"+tc.input+"}\n"), 0600)
			if !tc.invalid {
				partial, err := profile.Load(answers)
				if err != nil {
					t.Fatal(err)
				}
				if err = partial.Save(answers); err != nil {
					t.Fatal(err)
				}
			}
			code := 0
			if tc.invalid {
				code = 1
			}
			runCheckCLI(t, checkClient(t), root, code, "init", "--answers", answers)
			if tc.invalid {
				if _, err := os.Stat(filepath.Join(root, "cra")); !os.IsNotExist(err) {
					t.Fatal("invalid answers wrote evidence")
				}
				return
			}
			p, err := profile.Load(filepath.Join(root, "cra.yml"))
			if err != nil {
				t.Fatal(err)
			}
			if p.Classification.Answer != tc.want {
				t.Fatalf("class %s want %s", p.Classification.Answer, tc.want)
			}
		})
	}
}

func TestInitDecisionDatePresence(t *testing.T) {
	for _, tc := range []struct {
		name, fields string
		decided      bool
		want         *string
	}{
		{name: "supplied", fields: "decided_on: 2026-10-01", decided: true, want: strPtr("2026-10-01")},
		{name: "null decided", fields: "decided_on: null", decided: true},
		{name: "omitted decided", decided: true, want: strPtr(time.Now().Format("2006-01-02"))},
		{name: "unknown"}, {name: "null unknown", fields: "decided_on: null"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			put(t, root, "package.json", `{"name":"example","version":"1.0"}`)
			role, class := "unknown", "unknown"
			if tc.decided {
				role, class = "manufacturer", "default"
			}
			extra := ""
			if tc.fields != "" {
				extra = ", " + tc.fields
			}
			answers := filepath.Join(t.TempDir(), "answers.yml")
			os.WriteFile(answers, []byte("version: 1\nrole: {answer: "+role+extra+"}\nclassification: {answer: "+class+extra+"}\n"), 0600)
			runCheckCLI(t, checkClient(t), root, 0, "init", "--answers", answers)
			p, err := profile.Load(filepath.Join(root, "cra.yml"))
			if err != nil {
				t.Fatal(err)
			}
			for _, got := range []*string{p.Role.DecidedOn, p.Classification.DecidedOn} {
				if (got == nil) != (tc.want == nil) || got != nil && *got != *tc.want {
					t.Fatalf("date %v want %v", got, tc.want)
				}
			}
		})
	}
}
func strPtr(s string) *string { return &s }

func TestRejectedReleasePreservesReports(t *testing.T) {
	root := t.TempDir()
	release := t.TempDir()
	client := checkClient(t)
	put(t, root, "plugin.php", "<?php\n/* Plugin Name: Intended\nVersion: 1.0\n*/")
	put(t, root, "cra.yml", "version: 1\nrole: {answer: not-in-scope}\n")
	runCheckCLI(t, client, root, 0, "scan")
	runCheckCLI(t, client, root, 0, "docs")
	runCheckCLI(t, client, root, 0, "check")
	before := map[string]string{}
	entries, _ := os.ReadDir(filepath.Join(root, "cra/reports"))
	for _, e := range entries {
		before[e.Name()] = readFile(t, root, "cra/reports/"+e.Name())
	}
	put(t, release, "plugin.php", "<?php\n/* Plugin Name: Unrelated\nVersion: 1.0\n*/")
	runCheckCLI(t, client, root, 2, "scan", "--release", release)
	for file, b := range before {
		if readFile(t, root, "cra/reports/"+file) != b {
			t.Fatal("rejected release replaced", file)
		}
	}
	os.Remove(filepath.Join(release, "plugin.php"))
	put(t, release, "other.txt", "no metadata")
	var out, stderr bytes.Buffer
	code := newApp(client).RunIO([]string{"scan", "--dir", root, "--release", release, "--no-prompt"}, strings.NewReader(""), &out, &stderr)
	if code != 0 || !strings.Contains(out.String(), "Release identity unverified") {
		t.Fatal(code, out.String(), stderr.String())
	}
}

func exploitedClient(t *testing.T, queries *[][]string) *vulns.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/kev" {
			b, _ := os.ReadFile("../vulns/testdata/kev.json")
			w.Write(b)
			return
		}
		if r.URL.Path == "/v1/querybatch" {
			var q struct {
				Queries []struct {
					Package struct{ Name string }
					Version string
				}
			}
			json.NewDecoder(r.Body).Decode(&q)
			results := []any{}
			for _, entry := range q.Queries {
				*queries = append(*queries, []string{entry.Package.Name, entry.Version})
				ids := []any{}
				if entry.Package.Name == "guzzlehttp/guzzle" {
					ids = append(ids, map[string]string{"id": "GHSA-f2wf-25xc-69c9"})
				}
				results = append(results, map[string]any{"vulns": ids})
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
			return
		}
		b, err := os.ReadFile("../vulns/testdata/" + strings.TrimPrefix(r.URL.Path, "/v1/vulns/") + ".json")
		if err != nil {
			w.WriteHeader(404)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(server.Close)
	return &vulns.Client{HTTP: server.Client(), OSV: server.URL, KEV: server.URL + "/kev"}
}
func TestPrunedReleaseCoverageAndLookups(t *testing.T) {
	root := t.TempDir()
	release := t.TempDir()
	var queries [][]string
	client := exploitedClient(t, &queries)
	put(t, root, "composer.lock", `{"packages":[{"name":"guzzlehttp/guzzle","version":"7.4.0"},{"name":"maker/absent","version":"1.0"}]}`)
	put(t, root, "cra.yml", "version: 1\nrole: {answer: not-in-scope}\n")
	os.MkdirAll(filepath.Join(release, "vendor/guzzlehttp/guzzle/src"), 0755)
	put(t, release, "vendor/guzzlehttp/guzzle/src/Client.php", "<?php")
	put(t, release, "other.txt", "release")
	b := runCheckCLI(t, client, root, 0, "scan", "--release", release)
	var inv Report
	json.Unmarshal(b, &inv)
	found := false
	for _, c := range inv.Components {
		if c.PURL == "pkg:composer/guzzlehttp/guzzle" {
			found = true
			if c.Shipped != nil || c.Version != nil || c.LookupVersion != nil || c.Source.Path != "vendor/guzzlehttp/guzzle" {
				t.Fatal(c)
			}
		}
	}
	if !found || len(inv.CoverageGaps) == 0 {
		t.Fatal("missing unknown occurrence or gap", string(b))
	}
	guzzleQueries := 0
	for _, q := range queries {
		if q[0] == "guzzlehttp/guzzle" {
			guzzleQueries++
			if q[1] != "7.4.0" {
				t.Fatal("invented query", q)
			}
		}
	}
	if guzzleQueries != 1 {
		t.Fatal("release version guessed from lockfile", queries)
	}
	var bom struct {
		Components []struct{ Name, Version, Scope, PURL string }
	}
	json.Unmarshal([]byte(readFile(t, root, "cra/reports/sbom.cdx.json")), &bom)
	found = false
	for _, c := range bom.Components {
		if c.PURL == "pkg:composer/guzzlehttp/guzzle" {
			found = true
			if c.Version != "" || c.Scope != "required" {
				t.Fatal(c)
			}
		}
	}
	if !found {
		t.Fatal(bom)
	}
	var result status.Result
	json.Unmarshal(runCheckCLI(t, client, root, 0, "check"), &result)
	for _, item := range result.Items {
		if item.Name == "Known vulnerabilities" && item.State != status.Review {
			t.Fatal(item)
		}
	}
}
func TestShippingDecisionsSurviveInitAndTriage(t *testing.T) {
	for _, field := range []string{"", "shipped: true", "shipped: false", "shipped: null"} {
		t.Run(field, func(t *testing.T) {
			root := t.TempDir()
			release := t.TempDir()
			var queries [][]string
			client := exploitedClient(t, &queries)
			put(t, root, "composer.lock", `{"packages":[{"name":"guzzlehttp/guzzle","version":"7.4.0"}]}`)
			put(t, release, "other.txt", "no package files")
			answers := filepath.Join(t.TempDir(), "answers.yml")
			extra := ""
			if field != "" {
				extra = "\n   " + field + " # shipping decision"
			}
			os.WriteFile(answers, []byte("version: 1\nmanufacturer: {name: Example Maker}\nrole: {answer: manufacturer}\nclassification: {answer: default}\ncomponents:\n - path: vendor/guzzlehttp/guzzle # maker occurrence"+extra+"\n"), 0600)
			want := 0
			if field == "shipped: true" || field == "shipped: null" {
				want = 10
			}
			runCheckCLI(t, client, root, want, "init", "--answers", answers, "--release", release)
			p, err := profile.Load(filepath.Join(root, "cra.yml"))
			if err != nil {
				t.Fatal(err)
			}
			before := p.Components[0]
			var inv Report
			json.Unmarshal([]byte(readFile(t, root, "cra/reports/inventory.json")), &inv)
			c := inv.Components[0]
			if field == "shipped: null" && c.Shipped != nil {
				t.Fatal(c)
			}
			if field == "shipped: true" && (c.Shipped == nil || !*c.Shipped) {
				t.Fatal(c)
			}
			if (field == "" || field == "shipped: false") && (c.Shipped == nil || *c.Shipped) {
				t.Fatal(c)
			}
			var bom struct{ Components []struct{ Scope string } }
			json.Unmarshal([]byte(readFile(t, root, "cra/reports/sbom.cdx.json")), &bom)
			scope := "excluded"
			if want == 10 {
				scope = "required"
			}
			if bom.Components[0].Scope != scope {
				t.Fatal(bom)
			}
			runCheckCLI(t, client, root, want, "check")
			// A separate stale cause must not hide an unresolved exploited policy failure.
			if want == 10 {
				p.Product.Release = strPtr("replacement")
				if err = p.Save(filepath.Join(root, "cra.yml")); err != nil {
					t.Fatal(err)
				}
				runCheckCLI(t, client, root, 10, "check")
			}
			calls := len(queries)
			runCheckCLI(t, client, root, 0, "triage", "GHSA-f2wf-25xc-69c9", "--status", "under_investigation", "--reason", "Reviewing shipped usage")
			if len(queries) != calls {
				t.Fatal("triage made provider requests")
			}
			p, err = profile.Load(filepath.Join(root, "cra.yml"))
			if err != nil {
				t.Fatal(err)
			}
			after := p.Components[0]
			if before.ShippedSet != after.ShippedSet || (before.Shipped == nil) != (after.Shipped == nil) || before.Shipped != nil && *before.Shipped != *after.Shipped {
				t.Fatal("triage changed shipping decisions")
			}
			text := readFile(t, root, "cra.yml")
			if !strings.Contains(text, "# maker occurrence") || field == "" && strings.Contains(text, "shipped:") {
				t.Fatal(text)
			}
			runCheckCLI(t, client, root, want, "check")
		})
	}
}

func TestIncompleteOverrideRecovery(t *testing.T) {
	for _, absolute := range []bool{false, true} {
		t.Run(fmt.Sprint(absolute), func(t *testing.T) {
			if absolute {
				forceAbsolutePaths(t)
			}
			root := t.TempDir()
			release := t.TempDir()
			client := checkClient(t)
			put(t, root, "package.json", `{"name":"maker","version":"1.0"}`)
			put(t, release, "package.json", `{"name":"maker","version":"1.0"}`)
			put(t, root, "cra.yml", "version: 1\nrole: {answer: not-in-scope}\nproduct: {release: unused-saved-setting}\n")
			runCheckCLI(t, client, root, 0, "scan", "--release", release)
			runCheckCLI(t, client, root, 0, "check")
			runCheckCLI(t, client, root, 11, "scan", "--release", release, "--offline")
			runCheckCLI(t, client, root, 0, "docs")
			var current status.Result
			json.Unmarshal(runCheckCLI(t, client, root, 11, "check"), &current)
			match := regexp.MustCompile(`fendkit scan --release '([^']*)'`).FindStringSubmatch(strings.Join(current.Next, "\n"))
			if match == nil {
				t.Fatal("lost intentional override", current.Next)
			}
			runCheckCLI(t, client, root, 0, "scan", "--release", match[1])
			runCheckCLI(t, client, root, 0, "docs")
			runCheckCLI(t, client, root, 0, "check")
			var inv Report
			json.Unmarshal([]byte(readFile(t, root, "cra/reports/inventory.json")), &inv)
			if inv.Release == nil || *inv.Release != match[1] || inv.ReleaseConfiguration == nil || inv.ReleaseConfiguration.Setting == nil || *inv.ReleaseConfiguration.Setting != "unused-saved-setting" {
				t.Fatal(inv)
			}
		})
	}
}
