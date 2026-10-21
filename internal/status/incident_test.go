package status

import (
	"bytes"
	"github.com/vincentsch/fendkit/internal/detect"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vincentsch/fendkit/internal/incident"
	"github.com/vincentsch/fendkit/internal/vulns"
)

func TestIncidentActionsAndPolicyClock(t *testing.T) {
	root, p, s, v := fixture(t)
	v.Findings = []vulns.Finding{finding("ordinary-library", "high", true)}
	saveEvidence(t, root, s, v)
	check := func(now time.Time, want int) Result {
		t.Helper()
		r, e := Evaluate(root, p, now, false)
		if e != nil || r.ExitCode != want {
			t.Fatal(r, e)
		}
		return r
	}
	if check(frozenTime, 0).Items[12].State != NA {
		t.Fatal("no incidents must be not applicable")
	}
	rec := incident.Record{Version: 1, ID: "inc-1", Type: incident.Exploited, Title: "Reported exploitation", AwareAt: frozenTime, TimeZone: "UTC", Submissions: map[string]incident.Submission{}}
	if e := incident.Create(root, rec, nil); e != nil {
		t.Fatal(e)
	}
	r := check(frozenTime, 0)
	if r.Items[12].State != Review || !strings.HasPrefix(r.Next[0], "inc-1 early-warning:") || !strings.Contains(r.Next[0], "due in 24 h") || !strings.Contains(r.Next[2], "ordinary-library") {
		t.Fatal(r.Next, r.Items[12])
	}
	r = check(frozenTime.Add(25*time.Hour), 10)
	if !strings.Contains(r.Next[0], "overdue by 1 h") {
		t.Fatal(r.Next)
	}
	var terminalOutput, markdownOutput, htmlOutput bytes.Buffer
	Terminal(&terminalOutput, r, 80)
	Markdown(&markdownOutput, r)
	if e := HTML(&htmlOutput, r); e != nil {
		t.Fatal(e)
	}
	for _, output := range []string{r.Items[12].Explanation, terminalOutput.String(), markdownOutput.String(), htmlOutput.String()} {
		for _, boundary := range []string{"overdue by 1 h. inc-1 notification:", "due in 47 h. inc-1 final:"} {
			if !strings.Contains(output, boundary) {
				t.Fatalf("missing sentence break %q in %s", boundary, output)
			}
		}
	}
	if !strings.Contains(terminalOutput.String(), "fix-available inc-1. Review current deadlines") {
		t.Fatal("pending clock command runs into the next action", terminalOutput.String())
	}
	// Earlier deadlines win across different incidents, regardless of their ids.
	older := rec
	older.ID = "inc-2"
	older.AwareAt = frozenTime.Add(-time.Hour)
	if e := incident.Create(root, older, nil); e != nil {
		t.Fatal(e)
	}
	r = check(frozenTime.Add(25*time.Hour), 10)
	if !strings.HasPrefix(r.Next[0], "inc-2 early-warning:") {
		t.Fatal(r.Next)
	}
	rec.Submissions["early-warning"] = incident.Submission{SubmittedAt: frozenTime.Add(25 * time.Hour)}
	older.Submissions = rec.Submissions
	if e := incident.Save(root, rec); e != nil {
		t.Fatal(e)
	}
	if e := incident.Save(root, older); e != nil {
		t.Fatal(e)
	}
	r = check(frozenTime.Add(26*time.Hour), 0)
	for _, a := range r.Next {
		if strings.Contains(a, "early-warning:") {
			t.Fatal("filed stage remains an action", r.Next)
		}
	}
	// Submitted stages also stop being actions when the final clock was pending.
	for _, stage := range incident.Stages {
		rec.Submissions[stage] = incident.Submission{SubmittedAt: frozenTime.Add(26 * time.Hour)}
	}
	older.Submissions = rec.Submissions
	if e := incident.Save(root, rec); e != nil {
		t.Fatal(e)
	}
	if e := incident.Save(root, older); e != nil {
		t.Fatal(e)
	}
	r = check(frozenTime.Add(27*time.Hour), 0)
	if r.Items[12].State != Evidenced {
		t.Fatal(r.Items[12])
	}
	var terminal bytes.Buffer
	Terminal(&terminal, r, 80)
	if strings.Contains(terminal.String(), "Open incidents (none)") {
		t.Fatal(terminal.String())
	}
}
func TestIncidentPolicyPrecedesKnownExploitedAndIncompleteScan(t *testing.T) {
	root, p, s, v := fixture(t)
	f := finding("known-exploited", "critical", true)
	f.KnownExploited = true
	v.Findings = []vulns.Finding{f}
	s.Complete = false
	v.Complete = false
	saveEvidence(t, root, s, v)
	rec := incident.Record{Version: 1, ID: "inc-1", Type: incident.Severe, Title: "Severe incident", AwareAt: frozenTime.Add(-80 * time.Hour), TimeZone: "UTC", Submissions: map[string]incident.Submission{}}
	if e := incident.Create(root, rec, nil); e != nil {
		t.Fatal(e)
	}
	r := evaluate(t, root, p, false)
	if r.ExitCode != 10 || r.ScanComplete || !strings.HasPrefix(r.Next[0], "inc-1 early-warning:") || !strings.HasPrefix(r.Next[1], "inc-1 notification:") || !strings.Contains(r.Next[2], "Known exploited:") {
		t.Fatal(r.Next, r.ExitCode)
	}
}

func TestFinalReportingPolicyAndTimelySubmissions(t *testing.T) {
	for _, kind := range []string{incident.Exploited, incident.Severe} {
		t.Run(kind, func(t *testing.T) {
			root, p, _, _ := fixture(t)
			aware := frozenTime.Add(-45 * 24 * time.Hour)
			rec := incident.Record{Version: 1, ID: "inc-1", Type: kind, Title: "Reported incident", AwareAt: aware, TimeZone: "Europe/Berlin", Submissions: map[string]incident.Submission{
				"early-warning": {SubmittedAt: aware.Add(time.Hour)},
				"notification":  {SubmittedAt: aware.Add(48 * time.Hour)},
			}}
			if kind == incident.Exploited {
				fix := frozenTime.Add(-15 * 24 * time.Hour)
				rec.FixAvailableAt = &fix
			}
			if e := incident.Create(root, rec, nil); e != nil {
				t.Fatal(e)
			}
			r := evaluate(t, root, p, false)
			if r.ExitCode != 10 || !strings.HasPrefix(r.Next[0], "inc-1 final:") {
				t.Fatal(r.ExitCode, r.Next)
			}
			// A person who filed each stage by its deadline leaves no incident failure.
			finalDue := incident.Describe(rec, frozenTime).Stages[2].DueAt
			rec.Submissions["final"] = incident.Submission{SubmittedAt: finalDue.Add(-time.Hour)}
			if e := incident.Save(root, rec); e != nil {
				t.Fatal(e)
			}
			r = evaluate(t, root, p, false)
			if r.ExitCode != 0 || r.Items[12].State != Evidenced {
				t.Fatal(r.ExitCode, r.Items[12])
			}
		})
	}
}

func TestRecoveryBetweenPolicyAndUpcomingActions(t *testing.T) {
	root, p, s, v := fixture(t)
	s.Complete, v.Complete, s.Offline = false, false, true
	exploited := finding("exploited-library", "critical", true)
	exploited.KnownExploited = true
	v.Findings = []vulns.Finding{exploited, finding("ordinary-library", "high", true)}
	saveEvidence(t, root, s, v)
	rec := incident.Record{Version: 1, ID: "inc-1", Type: incident.Exploited, Title: "Exploitation", AwareAt: frozenTime.Add(-25 * time.Hour), TimeZone: "UTC", Submissions: map[string]incident.Submission{}}
	if err := incident.Create(root, rec, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "cra/reports/sbom.cdx.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "cra/user-information.md")); err != nil {
		t.Fatal(err)
	}
	r := evaluate(t, root, p, true)
	if r.ExitCode != 10 || r.Items[4].State != Missing || r.ScanState != "incomplete" {
		t.Fatal(r)
	}
	actions := rankActions(r)
	reordered := r
	reordered.Items = slices.Clone(r.Items)
	slices.Reverse(reordered.Items)
	for i := range reordered.Items {
		reordered.Items[i].Name = "Reworded heading"
		reordered.Items[i].Explanation = "Reworded explanation"
	}
	if got := rankActions(reordered); !reflect.DeepEqual(got, actions) {
		t.Fatal("presentation changed incident, policy or recovery priority", got, actions)
	}
	for i, text := range []string{"inc-1 early-warning:", "Known exploited:", "Review cra/user-information.md", r.ScanRecovery, "inc-1 notification:", "Update ordinary-library"} {
		if !strings.Contains(actions[i].text, text) {
			t.Fatal(actions)
		}
	}
	recoveryCount := 0
	for _, a := range actions {
		if a.text == r.ScanRecovery {
			recoveryCount++
		}
		if a.text == "Run fendkit scan." {
			t.Fatal("duplicate scan-only action")
		}
	}
	if recoveryCount != 1 || len(r.Next) != 5 {
		t.Fatal(r.Next)
	}
	p.Product.Version = detect.String("2.0.0")
	r = evaluate(t, root, p, true)
	found := false
	for _, a := range rankActions(r) {
		found = found || strings.HasPrefix(a.text, "Review product.version in cra.yml")
	}
	if !found {
		t.Fatal("product version repair lost")
	}
	p.Product.Version = nil
	for _, file := range []string{"cra/disclosure-policy.md", "cra/support-period.md", "cra/risk-assessment.md", "cra/technical-documentation.md"} {
		if err := os.Remove(filepath.Join(root, file)); err != nil {
			t.Fatal(err)
		}
	}
	r = evaluate(t, root, p, true)
	if slices.Contains(r.Next, r.ScanRecovery) {
		t.Fatal("policy actions should fill the five slots", r.Next)
	}
	var markdown, page bytes.Buffer
	Markdown(&markdown, r)
	if err := HTML(&page, r); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{markdown.String(), page.String()} {
		if !strings.Contains(text, "The last scan is incomplete.") || !strings.Contains(text, "incomplete (lookups did not run)") {
			t.Fatal("scan causes lost when urgent actions fill the limit")
		}
	}
}
