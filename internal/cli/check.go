package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	documents "github.com/vincentsch/conformline/internal/docs"
	"github.com/vincentsch/conformline/internal/profile"
	"github.com/vincentsch/conformline/internal/status"
	"github.com/vincentsch/rungrad"
)

type checkExit struct{ code int }

func (e *checkExit) Error() string { return "Status needs attention" }
func (e *checkExit) ExitCode() int { return e.code }
func checkCommand(dir *string) *rungrad.Command {
	return &rungrad.Command{Use: "check", Short: "Show evidence status and the next actions", Long: "Read cra.yml, documents and saved scan evidence without network calls.\nWrite cra/reports/status.md, status.html and refresh cra/README.md.\nExit 10 for overdue unsubmitted incident stages or unresolved shipped CISA KEV findings; --strict also fails on missing applicable items.\nOtherwise exit 11 for missing, mixed, incomplete or stale scans; exit 0 for current evidence.\nScans become stale after seven days, inventory changes or product version changes.\n--ci appends the Markdown report to GITHUB_STEP_SUMMARY when set.\nUse --dry-run to evaluate without writing reports or the CI summary.", Examples: []string{"conformline check", "conformline check --strict --ci", "conformline check --json"}, Mutates: true, OutputModes: []string{rungrad.OutputModeHuman, rungrad.OutputModeJSON}, Args: cobra.NoArgs,
		Configure: func(cmd *cobra.Command) {
			cmd.Flags().Bool("strict", false, "Treat missing applicable items as policy failures")
			cmd.Flags().Bool("ci", false, "Append Markdown status to GITHUB_STEP_SUMMARY when set")
		},
		Run: func(f *rungrad.Factory, cmd *cobra.Command, _ []string) error {
			p, e := profile.Load(filepath.Join(*dir, "cra.yml"))
			if os.IsNotExist(e) {
				return rungrad.NewError(1, "Run `conformline init` first; check needs cra.yml")
			}
			if e != nil {
				return rungrad.NewError(1, "Cannot load cra.yml: "+safeError(e))
			}
			strict, _ := cmd.Flags().GetBool("strict")
			r, e := evaluateStatus(*dir, p, strict, f.DryRun())
			if e != nil {
				return e
			}
			ci, _ := cmd.Flags().GetBool("ci")
			if ci && !f.DryRun() {
				if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
					var b strings.Builder
					status.Markdown(&b, r)
					file, e := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
					if e != nil {
						return rungrad.NewError(2, "Cannot write GITHUB_STEP_SUMMARY; check the job summary path and permissions")
					}
					_, e = io.WriteString(file, b.String()+"\n")
					ce := file.Close()
					if e != nil || ce != nil {
						return rungrad.NewError(2, "Cannot write GITHUB_STEP_SUMMARY; check free space and permissions")
					}
				}
			}
			if e = f.WriteResult(r, func(w io.Writer) { status.Terminal(w, r, status.OutputWidth(f.Stdout)) }); e != nil {
				return e
			}
			if r.ExitCode != 0 {
				return &checkExit{r.ExitCode}
			}
			return nil
		}}
}
func evaluateStatus(root string, p *profile.Profile, strict, dry bool) (status.Result, error) {
	r, e := status.Evaluate(root, p, time.Now().UTC(), strict)
	if e != nil {
		return r, rungrad.NewError(2, e.Error())
	}
	r.DryRun = dry
	if !dry {
		if e = status.Write(root, r); e != nil {
			return r, rungrad.NewError(2, e.Error())
		}
		if e = documents.WriteIndex(root, p, time.Now().UTC(), r.Next, status.ScanLabel(r), false); e != nil {
			return r, rungrad.NewError(2, e.Error())
		}
	}
	return r, nil
}
