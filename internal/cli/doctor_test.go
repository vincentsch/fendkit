package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vincentsch/conformline/internal/version"
	"github.com/vincentsch/conformline/internal/vulns"
	"github.com/vincentsch/rungrad/testutil"
)

func TestDoctorSetupCoverageAndConnections(t *testing.T) {
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "conformline/"+version.Version {
			t.Errorf("User-Agent = %q", got)
		}
		if fail.Load() {
			w.WriteHeader(503)
			return
		}
		if r.URL.Path == "/v1/querybatch" {
			var q struct {
				Queries []any `json:"queries"`
			}
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&q) != nil || len(q.Queries) != 0 {
				t.Error("doctor disclosed project data or used an invalid probe")
			}
		}
		ioJSON(w, `{}`)
	}))
	defer server.Close()
	client := &vulns.Client{HTTP: server.Client(), OSV: server.URL, KEV: server.URL + "/kev"}
	run := func(root string, code int) doctorResult {
		t.Helper()
		result := testutil.RunWith(newApp(client), testutil.Options{}, "doctor", "--dir", root, "--json")
		if result.Exit != code || result.Stderr != "" || !json.Valid([]byte(result.Stdout)) {
			t.Fatalf("%+v", result)
		}
		var r doctorResult
		json.Unmarshal([]byte(result.Stdout), &r)
		for _, check := range r.Checks {
			if check.Fix == "" {
				t.Fatal(check)
			}
		}
		return r
	}
	find := func(r doctorResult, name, level, part string) {
		t.Helper()
		for _, check := range r.Checks {
			if check.Name == name && check.Level == level && strings.Contains(check.Message, part) {
				return
			}
		}
		t.Fatalf("missing %s %s %s: %+v", name, level, part, r)
	}
	root := t.TempDir()
	copyTree(t, "../../testdata/products/npm-library", root)
	put(t, root, "pnpm-lock.yaml", "lockfileVersion: 9")
	put(t, root, "yarn.lock", "# lockfile")
	r := run(root, 0)
	find(r, "cra.yml", "information", "Not created")
	find(r, "Dependency coverage", "warning", "pnpm-lock.yaml")
	find(r, "Dependency coverage", "warning", "yarn.lock")
	find(r, "Dependency coverage", "warning", "no resolved runtime version")
	find(r, "Dependency coverage", "warning", "package-lock.json")
	if _, err := os.Stat(filepath.Join(root, "cra.yml")); !os.IsNotExist(err) {
		t.Fatal("doctor wrote profile")
	}
	if _, err := os.Stat(filepath.Join(root, "cra")); !os.IsNotExist(err) {
		t.Fatal("doctor wrote reports")
	}
	put(t, root, "cra.yml", "version: 999\n")
	find(run(root, 2), "cra.yml", "problem", "version")
	put(t, root, "cra.yml", "version: 1\nrole: {answer: unknown}\n")
	find(run(root, 0), "cra.yml", "ok", "valid")
	fail.Store(true)
	r = run(root, 2)
	find(r, "OSV.dev", "problem", "HTTP 503")
	find(r, "CISA KEV", "problem", "HTTP 503")
	fail.Store(false)
	find(run(filepath.Join(root, "missing"), 2), "Repository", "problem", "cannot read")
}

func TestDoctorReleaseAmbiguityAndStableTag(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ioJSON(w, `{}`) }))
	defer server.Close()
	client := &vulns.Client{HTTP: server.Client(), OSV: server.URL, KEV: server.URL}
	root := t.TempDir()
	copyTree(t, "../../testdata/wp-plugin/acme-booking", root)
	copyTree(t, "../../testdata/wp-plugin/dist", filepath.Join(root, "dist"))
	zip, err := os.ReadFile(filepath.Join(root, "dist/acme-booking-2.3.1.zip"))
	if err != nil {
		t.Fatal(err)
	}
	put(t, root, "dist/other-2.3.1.zip", string(zip))
	put(t, root, "readme.txt", "Stable tag: 2.2.0\n")
	result := testutil.RunWith(newApp(client), testutil.Options{}, "doctor", "--dir", root)
	if result.Exit != 2 || !strings.Contains(result.Stdout, "Several release ZIPs match") || !strings.Contains(result.Stdout, "Stable tag 2.2.0") || !strings.Contains(result.Stdout, "Fix:") {
		t.Fatalf("%+v", result)
	}
	put(t, root, "cra.yml", "version: 1\nproduct: {release: dist/acme-booking-2.3.1.zip}\n")
	result = testutil.RunWith(newApp(client), testutil.Options{}, "doctor", "--dir", root)
	if result.Exit != 0 || !strings.Contains(result.Stdout, "ok  Release: dist/acme-booking-2.3.1.zip") {
		t.Fatalf("%+v", result)
	}
}
