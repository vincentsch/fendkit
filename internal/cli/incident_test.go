package cli

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincentsch/fendkit/internal/incident"
	"github.com/vincentsch/fendkit/internal/profile"
	"github.com/vincentsch/fendkit/internal/status"
	"github.com/vincentsch/rungrad"
	"github.com/vincentsch/rungrad/testutil"
)

func TestIncidentLifecycle(t *testing.T) {
	t.Setenv("TZ", "Europe/Berlin")
	root := t.TempDir()
	copyTree(t, "../../testdata/wp-plugin/acme-booking", root)
	put(t, root, "cra.yml", "version: 1\nmanufacturer: {name: Example Maker}\nrole: {answer: manufacturer}\n")
	clock := time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC)
	run := func(want int, args ...string) testutil.Result {
		t.Helper()
		app := rungrad.New(rungrad.AppConfig{Name: "fendkit"})
		app.AddCommand(incidentCommand(&root, func() time.Time { return clock }))
		r := testutil.Run(app, append([]string{"incident"}, args...)...)
		if r.Exit != want {
			t.Fatalf("%v: %+v", args, r)
		}
		if strings.Contains(strings.Join(args, " "), "--json") {
			output := r.Stdout
			if want != 0 {
				output = r.Stderr
			}
			if !json.Valid([]byte(output)) {
				t.Fatalf("invalid JSON: %+v", r)
			}
		}
		return r
	}
	run(0, "list", "--json")
	run(1, "new", "--type", incident.Exploited, "--title", "Reported exploitation", "--no-prompt")
	if _, e := os.Stat(filepath.Join(root, "cra")); !os.IsNotExist(e) {
		t.Fatal("refusal wrote files")
	}
	run(0, "new", "--type", incident.Exploited, "--title", "Reported exploitation", "--confirm", "--dry-run", "--json")
	if _, e := os.Stat(filepath.Join(root, "cra")); !os.IsNotExist(e) {
		t.Fatal("preview wrote files")
	}
	run(0, "new", "--type", incident.Exploited, "--title", "Reported exploitation", "--aware", "2026-10-24 10:00", "--json")
	first, e := incident.Load(root, "inc-1")
	if e != nil || !first.AwareAt.Equal(clock) || first.TimeZone != "Europe/Berlin" {
		t.Fatal(first, e)
	}
	run(0, "new", "--type", incident.Severe, "--title", "Service disruption", "--confirm", "--no-prompt")
	if r := run(0, "show", "inc-1"); !strings.Contains(r.Stdout, "Pending:") || !strings.Contains(r.Stdout, "2026-10-25 09:00:00 CET") {
		t.Fatal(r)
	}
	// Maker edits survive every record update, including preview and corrected filings.
	hashes := map[string][32]byte{}
	for _, id := range []string{"inc-1", "inc-2"} {
		for _, name := range []string{"early-warning.md", "notification.md", "final-report.md", "user-notice.md"} {
			file := "cra/incidents/" + id + "/" + name
			body := readFile(t, root, file) + "\nMaker-reviewed filing text.\n"
			put(t, root, file, body)
			hashes[file] = sha256.Sum256([]byte(body))
		}
	}
	run(0, "fix-available", "inc-1", "--at", "2026-10-25 11:00", "--dry-run", "--json")
	first, _ = incident.Load(root, "inc-1")
	if first.FixAvailableAt != nil {
		t.Fatal("preview saved fix")
	}
	run(0, "fix-available", "inc-1", "--at", "2026-10-25 11:00", "--json")
	if r := run(0, "show", "inc-1"); !strings.Contains(r.Stdout, "2026-11-08 11:00:00 CET") {
		t.Fatal(r)
	}
	before := run(0, "show", "inc-2", "--json").Stdout
	run(0, "submitted", "inc-2", "--stage", "notification", "--at", "2026-10-26T12:00:00Z", "--json")
	after := run(0, "show", "inc-2", "--json").Stdout
	if before == after || !strings.Contains(after, "2026-11-26") || !strings.Contains(before, "Provisional") {
		t.Fatal(before, after)
	}
	for _, id := range []string{"inc-1", "inc-2"} {
		for _, stage := range incident.Stages {
			run(0, "submitted", id, "--stage", stage, "--at", "2026-11-01T12:00:00Z", "--json")
		}
	}
	clock = time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)
	p, e := profile.Load(filepath.Join(root, "cra.yml"))
	if e != nil {
		t.Fatal(e)
	}
	result, e := status.Evaluate(root, p, clock, false)
	if e != nil || result.Items[12].State != status.Evidenced || result.ExitCode != 11 {
		t.Fatal(result, e)
	}
	for file, hash := range hashes {
		b, e := os.ReadFile(filepath.Join(root, file))
		if e != nil || sha256.Sum256(b) != hash {
			t.Fatal("draft changed", file, e)
		}
	}
	for _, args := range [][]string{{"show", "inc-99"}, {"submitted", "inc-99", "--stage", "final"}, {"fix-available", "inc-99"}, {"show", "../inc-1"}} {
		run(5, append(args, "--json")...)
	}
	for _, args := range [][]string{
		{"fix-available", "inc-2"}, {"submitted", "inc-1", "--stage", "invalid"},
		{"submitted", "inc-1", "--stage", "final", "--at", "2020-01-01T00:00:00Z"},
		{"new", "--type", "invalid", "--title", "Test", "--confirm"},
		{"new", "--type", incident.Exploited, "--aware", "invalid", "--title", "Test"},
	} {
		run(1, append(args, "--json")...)
	}
}
func TestAwarenessPromptAndLegalWording(t *testing.T) {
	t.Setenv("TZ", "Europe/Berlin")
	for _, answer := range []string{"yes\n", "no\n", "\n"} {
		t.Run(strings.TrimSpace(answer), func(t *testing.T) {
			root := t.TempDir()
			put(t, root, "cra.yml", "version: 1\n")
			put(t, root, "package.json", `{"name":"sample","version":"1.0.0"}`)
			app := rungrad.New(rungrad.AppConfig{Name: "fendkit"})
			app.AddCommand(incidentCommand(&root, func() time.Time { return time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC) }))
			r := testutil.RunWith(app, testutil.Options{Stdin: strings.NewReader(answer), Terminal: true, TerminalSet: true}, "incident", "new", "--type", incident.Severe, "--title", "Disruption")
			want := 1
			if answer == "yes\n" {
				want = 0
			}
			if r.Exit != want || !strings.Contains(r.Stderr, "Europe/Berlin") {
				t.Fatal(r)
			}
			if want == 0 {
				text := r.Stdout
				for _, name := range []string{"early-warning.md", "notification.md", "final-report.md", "user-notice.md"} {
					draft := readFile(t, root, "cra/incidents/inc-1/"+name)
					if !strings.HasPrefix(draft, "Awareness time:") || !strings.Contains(draft, "fendkit incident show inc-1") || !strings.Contains(draft, "Check the live form") || !strings.Contains(draft, incident.Legal) {
						t.Fatal(draft)
					}
					text += draft
				}
				for _, bad := range []string{"compliant product", "cra compliant", "certified", "guarantee", "ensures compliance", "cra-ready"} {
					if strings.Contains(strings.ToLower(text), bad) {
						t.Fatal("forbidden wording", bad)
					}
				}
			}
		})
	}
}
func TestIncidentCheckPolicyWithIncompleteScan(t *testing.T) {
	root := t.TempDir()
	put(t, root, "package.json", `{"name":"sample","version":"1.0.0"}`)
	put(t, root, "cra.yml", "version: 1\nrole: {answer: manufacturer}\n")
	empty := runCheckCLI(t, nil, root, 11, "check", "--dry-run")
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(empty, &fields); e != nil {
		t.Fatal(e)
	}
	if string(fields["incidents"]) != "[]" {
		t.Fatalf("empty incidents must be an array: %s", fields["incidents"])
	}
	runCheckCLI(t, nil, root, 0, "incident", "new", "--type", incident.Exploited, "--title", "Active exploitation", "--aware", "2020-01-01T10:00:00Z")
	b := runCheckCLI(t, nil, root, 10, "check")
	var r status.Result
	if e := json.Unmarshal(b, &r); e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(r.Next[0], "inc-1 early-warning:") || r.ScanComplete {
		t.Fatal(r)
	}
	for _, stage := range []string{"early-warning", "notification"} {
		runCheckCLI(t, nil, root, 0, "incident", "submitted", "inc-1", "--stage", stage)
	}
	b = runCheckCLI(t, nil, root, 11, "check")
	json.Unmarshal(b, &r)
	if r.Items[12].State != status.Review || !strings.Contains(r.Items[12].Explanation, "Pending:") {
		t.Fatal(r)
	}
}

func TestIncidentAdvisoryFromSavedFindings(t *testing.T) {
	root := t.TempDir()
	put(t, root, "package.json", `{"name":"sample","version":"1.0.0"}`)
	put(t, root, "cra.yml", "version: 1\n")
	if e := os.MkdirAll(filepath.Join(root, "cra/reports"), 0755); e != nil {
		t.Fatal(e)
	}
	put(t, root, "cra/reports/vulnerabilities.json", `{"complete":true,"findings":[{"ids":["GHSA-example","CVE-example"],"component":{"name":"library","version":"1.0.0"},"advisories":[{"id":"GHSA-example","summary":"Facts from saved findings"}]}]}`)
	runCheckCLI(t, nil, root, 0, "incident", "new", "--type", incident.Exploited, "--title", "Exploited library", "--aware", "2026-10-20T10:00:00Z", "--advisory", "CVE-example")
	if !strings.Contains(readFile(t, root, "cra/incidents/inc-1/notification.md"), "Facts from saved findings") {
		t.Fatal("no advisory prefill")
	}
	runCheckCLI(t, nil, root, 5, "incident", "new", "--type", incident.Exploited, "--title", "Exploited library", "--aware", "2026-10-20T10:00:00Z", "--advisory", "unknown")
}

func TestChecklistIncidentCommandsAndPreservation(t *testing.T) {
	root := t.TempDir()
	put(t, root, "package.json", `{"name":"sample","version":"1.0.0"}`)
	put(t, root, "cra.yml", "version: 1\nrole: {answer: manufacturer}\n")
	runCheckCLI(t, nil, root, 0, "docs")
	file := "cra/incident-checklist.md"
	text := readFile(t, root, file)
	for _, command := range []string{"incident new", "incident list", "incident show <id>", "incident fix-available <id>", "incident submitted <id> --stage early-warning"} {
		if !strings.Contains(text, command) {
			t.Fatal("missing command", command)
		}
	}
	put(t, root, file, text+"\nMaker response procedure.\n")
	before := sha256.Sum256([]byte(readFile(t, root, file)))
	runCheckCLI(t, nil, root, 0, "docs")
	runCheckCLI(t, nil, root, 0, "incident", "new", "--type", incident.Severe, "--title", "Disruption", "--confirm")
	if before != sha256.Sum256([]byte(readFile(t, root, file))) {
		t.Fatal("existing checklist changed")
	}
}

func TestFixAvailableBeforeAwareness(t *testing.T) {
	root := t.TempDir()
	put(t, root, "package.json", `{"name":"sample","version":"1.0.0"}`)
	put(t, root, "cra.yml", "version: 1\nrole: {answer: manufacturer}\n")
	aware := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	available := aware.Add(-20 * 24 * time.Hour)
	clock := aware.Add(time.Hour)
	run := func(args ...string) testutil.Result {
		t.Helper()
		app := rungrad.New(rungrad.AppConfig{Name: "fendkit"})
		app.AddCommand(incidentCommand(&root, func() time.Time { return clock }))
		result := testutil.Run(app, append([]string{"incident"}, args...)...)
		if result.Exit != 0 {
			t.Fatalf("%v: %+v", args, result)
		}
		return result
	}
	run("new", "--type", incident.Exploited, "--title", "Reported exploitation after patch", "--aware", aware.Format(time.RFC3339))
	drafts := map[string]string{}
	for _, file := range []string{"early-warning.md", "notification.md", "final-report.md", "user-notice.md"} {
		path := "cra/incidents/inc-1/" + file
		drafts[path] = readFile(t, root, path) + "\nMaker's edited text.\n"
		put(t, root, path, drafts[path])
	}
	run("fix-available", "inc-1", "--at", available.Format(time.RFC3339))
	record, err := incident.Load(root, "inc-1")
	if err != nil || record.FixAvailableAt == nil || !record.FixAvailableAt.Equal(available) || !record.AwareAt.Equal(aware) {
		t.Fatal(record, err)
	}
	view := incident.Describe(record, clock)
	final := view.Stages[2]
	if final.DueAt == nil || !final.DueAt.Equal(available.Add(14*24*time.Hour)) || !final.Overdue {
		t.Fatal(final)
	}
	p, err := profile.Load(filepath.Join(root, "cra.yml"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := status.Evaluate(root, p, clock, false)
	if err != nil || result.ExitCode != 10 || !strings.Contains(result.Next[0], "final") {
		t.Fatal(result, err)
	}
	shown := run("show", "inc-1", "--json")
	if !strings.Contains(shown.Stdout, final.DueAt.Format(time.RFC3339)) {
		t.Fatal(shown)
	}
	for path, want := range drafts {
		if got := readFile(t, root, path); got != want {
			t.Fatalf("draft changed: %s", path)
		}
	}
}
