package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vincentsch/conformline/internal/detect"
	"github.com/vincentsch/conformline/internal/incident"
	"github.com/vincentsch/conformline/internal/profile"
	"github.com/vincentsch/conformline/internal/vulns"
	"github.com/vincentsch/rungrad"
)

type incidentResult struct {
	LegalNotice string          `json:"legal_notice"`
	DryRun      bool            `json:"dry_run"`
	Message     string          `json:"message"`
	Incidents   []incident.View `json:"incidents"`
}

func writeIncidents(f *rungrad.Factory, records []incident.Record, now time.Time, message string) error {
	r := incidentResult{LegalNotice: incident.Legal, DryRun: f.DryRun(), Message: message, Incidents: []incident.View{}}
	for _, rec := range records {
		r.Incidents = append(r.Incidents, incident.Describe(rec, now))
	}
	return f.WriteResult(r, func(w io.Writer) {
		if f.DryRun() {
			fmt.Fprintln(w, "DRY RUN: no files changed.")
		}
		if message != "" {
			fmt.Fprintln(w, message)
		}
		if len(records) == 0 {
			fmt.Fprintln(w, "No incidents recorded.")
		}
		for _, v := range r.Incidents {
			fmt.Fprintf(w, "\n%s: %s (%s)\nAwareness: %s\n", v.Record.ID, v.Record.Title, v.Record.Type, v.Awareness)
			if v.Record.Advisory != nil {
				fmt.Fprintln(w, "Advisory: "+*v.Record.Advisory)
			}
			if v.Record.Notes != "" {
				fmt.Fprintln(w, "Notes: "+v.Record.Notes)
			}
			if v.NextStage != nil {
				fmt.Fprintf(w, "Next: %s — %s\nFiling text: %s\n", v.NextStage.Name, v.NextStage.Description, v.NextStage.Draft)
			} else {
				fmt.Fprintln(w, "All required reporting stages are recorded as submitted.")
			}
			for _, s := range v.Stages {
				fmt.Fprintf(w, "  %s: %s\n    Filing text: %s\n", s.Name, s.Description, s.Draft)
			}
			fmt.Fprintf(w, "  User notice: cra/incidents/%s/user-notice.md; inform users without undue delay.\n", v.Record.ID)
			if v.Record.FixAvailableAt != nil {
				fmt.Fprintln(w, "Fix or mitigation available: "+incident.FormatTime(*v.Record.FixAvailableAt, v.Record.TimeZone))
			}
		}
		fmt.Fprintln(w, "\n"+incident.Legal)
	})
}
func incidentError(e error) error {
	if os.IsNotExist(e) {
		return rungrad.NewError(5, "Incident not found; use conformline incident list to find a recorded id")
	}
	return rungrad.NewError(2, "Cannot read or save incidents: "+safeError(e))
}
func incidentCommand(dir *string, now func() time.Time) *rungrad.Command {
	root := &rungrad.Command{Use: "incident", Short: "Record awareness, reporting deadlines and filing drafts", Long: "The maker decides when they became aware. Conformline prepares drafts locally.\nA person submits in ENISA's Single Reporting Platform; submitted only records that filing.", Examples: []string{"conformline incident list"}}
	modes := []string{rungrad.OutputModeHuman, rungrad.OutputModeJSON}
	newCmd := &rungrad.Command{Use: "new", Short: "Record an incident and create filing drafts", Long: "Requires cra.yml. Drafts use saved findings only, without network calls.\n--aware accepts RFC 3339 or YYYY-MM-DD HH:MM in the local IANA time zone.\nWithout --aware, confirm the proposed current time with --confirm or yes at the prompt.\nIn non-interactive or JSON use, pass --aware or --confirm.\nThe recorded zone comes from TZ, the /etc/localtime link, or UTC.\nDrafts are created once; incident show always gives the current deadlines.\nUse --dry-run to preview without writing files.", Examples: []string{"conformline incident new --type exploited-vulnerability --title 'Active exploitation' --aware '2026-10-20T10:00:00+02:00'", "conformline incident new --type severe-incident --title 'Service disruption' --confirm"}, Mutates: true, OutputModes: modes, Args: cobra.NoArgs,
		Configure: func(c *cobra.Command) {
			c.Flags().String("type", "", "exploited-vulnerability or severe-incident (required)")
			c.Flags().String("title", "", "Short incident description (required)")
			c.Flags().String("aware", "", "Maker's awareness time: RFC 3339 or YYYY-MM-DD HH:MM")
			c.Flags().String("advisory", "", "Advisory id or alias from saved findings (optional)")
			c.Flags().Bool("confirm", false, "Confirm the proposed current awareness time")
		}, Run: func(f *rungrad.Factory, c *cobra.Command, _ []string) error {
			get := func(k string) string { s, _ := c.Flags().GetString(k); return strings.TrimSpace(s) }
			kind, title := get("type"), get("title")
			if kind != incident.Exploited && kind != incident.Severe {
				return rungrad.NewError(1, "--type must be exploited-vulnerability or severe-incident")
			}
			if title == "" {
				return rungrad.NewError(1, "--title is required; describe the incident")
			}
			p, e := profile.Load(filepath.Join(*dir, "cra.yml"))
			if os.IsNotExist(e) {
				return rungrad.NewError(1, "Run `conformline init` first; incident new needs cra.yml")
			}
			if e != nil {
				return rungrad.NewError(1, "Cannot load cra.yml: "+safeError(e))
			}
			id, e := incident.NextID(*dir)
			if e != nil {
				return incidentError(e)
			}
			z := incident.LocalZone()
			clock := now()
			aware := clock
			if s := get("aware"); s != "" {
				aware, e = incident.ParseTime(s, z)
				if e != nil {
					return rungrad.NewError(1, "Invalid --aware: "+e.Error())
				}
			} else {
				confirmed, _ := c.Flags().GetBool("confirm")
				if !confirmed {
					proposed := "Proposed awareness: " + incident.FormatTime(aware, z.String())
					if !f.CanPrompt() {
						return rungrad.NewError(1, proposed+". Awareness is your decision; pass --aware or --confirm")
					}
					var input TextInput
					answer, e := input.Ask(f, proposed+". Record this as your awareness time? [yes/no]")
					if e != nil {
						return e
					}
					if !strings.EqualFold(answer, "yes") && !strings.EqualFold(answer, "y") {
						return rungrad.NewError(1, "Awareness was not confirmed; pass --aware with the time you became aware")
					}
				}
			}
			r := incident.Record{Version: 1, ID: id, Type: kind, Title: title, AwareAt: aware, TimeZone: z.String(), Submissions: map[string]incident.Submission{}}
			if a := get("advisory"); a != "" {
				r.Advisory = &a
			}
			product, e := detect.Detect(*dir)
			if e != nil {
				return rungrad.NewError(2, e.Error())
			}
			var saved vulns.Report
			b, readErr := os.ReadFile(filepath.Join(*dir, "cra/reports/vulnerabilities.json"))
			message := "Created incident record and four filing drafts."
			if r.Advisory != nil {
				if readErr != nil || json.Unmarshal(b, &saved) != nil {
					return rungrad.NewError(1, "--advisory needs readable saved findings; run conformline scan first or omit --advisory")
				}
				found := slices.ContainsFunc(saved.Findings, func(f vulns.Finding) bool { return slices.Contains(f.IDs, *r.Advisory) })
				if !found {
					return rungrad.NewError(5, "Advisory not found in saved findings; check cra/reports/vulnerabilities.md or omit --advisory")
				}
				if !saved.Complete {
					message += " Saved scan is incomplete; verify advisory details before filing."
				}
			}
			drafts := incident.Drafts(r, p, product, saved.Findings)
			if !f.DryRun() {
				if e = incident.Create(*dir, r, drafts); e != nil {
					return incidentError(e)
				}
			} else {
				message = "Would create incident record and four filing drafts."
			}
			return writeIncidents(f, []incident.Record{r}, clock, message)
		}}
	list := &rungrad.Command{Use: "list", Short: "List incidents with deadlines and submission status", Long: "Read saved incident records and calculate current deadlines locally.\nNo network calls or file changes.", Examples: []string{"conformline incident list", "conformline incident list --json"}, OutputModes: modes, Args: cobra.NoArgs, Run: func(f *rungrad.Factory, _ *cobra.Command, _ []string) error {
		records, e := incident.List(*dir)
		if e != nil {
			return incidentError(e)
		}
		return writeIncidents(f, records, now(), "")
	}}
	show := &rungrad.Command{Use: "show <id>", Short: "Show current deadlines and paths to filing texts", Long: "Show outstanding and submitted stages, remaining time and the four draft paths.\nThe final clock waits for a fix for exploited vulnerabilities. Severe incidents use\na provisional notification due time until actual submission is recorded.", Examples: []string{"conformline incident show inc-1"}, OutputModes: modes, Args: cobra.ExactArgs(1), Run: func(f *rungrad.Factory, _ *cobra.Command, args []string) error {
		r, e := incident.Load(*dir, args[0])
		if e != nil {
			return incidentError(e)
		}
		return writeIncidents(f, []incident.Record{r}, now(), "")
	}}
	newCmd.Related = []string{"incident show", "incident list", "check"}
	list.Related = []string{"incident show", "incident new", "check"}
	show.Related = []string{"incident submitted", "incident fix-available", "incident list"}
	root.AddCommand(newCmd, list, show)
	for _, operation := range []string{"submitted", "fix-available"} {
		op := operation
		short := "Record when a fix or mitigation became available"
		long := "For exploited vulnerabilities only. Starts the elapsed 14-day final-report clock."
		example := "conformline incident fix-available inc-1 --at '2026-10-21 12:00'"
		if op == "submitted" {
			short = "Record a person's filing in ENISA's platform"
			long = "Records a filing only; nothing is sent. A recorded stage stops being overdue.\nRecording notification submission recalculates the severe-incident final deadline."
			example = "conformline incident submitted inc-1 --stage early-warning"
		}
		cmd := &rungrad.Command{Use: op + " <id>", Short: short, Long: long + "\n--at accepts RFC 3339 or YYYY-MM-DD HH:MM in the local zone; defaults to now.\nAll times display in the incident's recorded time zone. Existing drafts are preserved.\nUse --dry-run to preview without changing the record.", Examples: []string{example}, Mutates: true, OutputModes: modes, Args: cobra.ExactArgs(1), Configure: func(c *cobra.Command) {
			c.Flags().String("at", "", "Recorded time; defaults to now (RFC 3339 or local YYYY-MM-DD HH:MM)")
			if op == "submitted" {
				c.Flags().String("stage", "", "early-warning, notification, or final (required)")
			}
		}, Run: func(f *rungrad.Factory, c *cobra.Command, args []string) error {
			r, e := incident.Load(*dir, args[0])
			if e != nil {
				return incidentError(e)
			}
			clock := now()
			at := clock
			s, _ := c.Flags().GetString("at")
			if s != "" {
				at, e = incident.ParseTime(s, incident.LocalZone())
				if e != nil {
					return rungrad.NewError(1, "Invalid --at: "+e.Error())
				}
			}
			if at.Before(r.AwareAt) {
				return rungrad.NewError(1, "--at must be on or after the recorded awareness time")
			}
			message := "Recorded fix or mitigation availability at " + incident.FormatTime(at, r.TimeZone) + "."
			if op == "submitted" {
				stage, _ := c.Flags().GetString("stage")
				if !slices.Contains(incident.Stages, stage) {
					return rungrad.NewError(1, "--stage must be early-warning, notification, or final")
				}
				r.Submissions[stage] = incident.Submission{SubmittedAt: at}
				message = "Recorded " + stage + " submission at " + incident.FormatTime(at, r.TimeZone) + ". Nothing was sent."
			} else {
				if r.Type != incident.Exploited {
					return rungrad.NewError(1, "fix-available applies only to exploited-vulnerability incidents")
				}
				r.FixAvailableAt = &at
			}
			if !f.DryRun() {
				if e = incident.Save(*dir, r); e != nil {
					return incidentError(e)
				}
			} else {
				message = "Would update incident record. " + message
			}
			return writeIncidents(f, []incident.Record{r}, clock, message)
		}}
		cmd.Related = []string{"incident show", "incident list", "check"}
		root.AddCommand(cmd)
	}
	return root
}
