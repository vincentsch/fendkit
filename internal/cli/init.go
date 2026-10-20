package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/vincentsch/conformline/internal/detect"
	documents "github.com/vincentsch/conformline/internal/docs"
	"github.com/vincentsch/conformline/internal/inventory"
	"github.com/vincentsch/conformline/internal/profile"
	"github.com/vincentsch/conformline/internal/status"
	"github.com/vincentsch/conformline/internal/vulns"
	"github.com/vincentsch/rungrad"
)

type initResult struct {
	Profile   string           `json:"profile"`
	Scan      Report           `json:"scan"`
	Documents documents.Result `json:"documents"`
	Status    status.Result    `json:"status"`
}

func initCommand(dir *string, client *vulns.Client) *rungrad.Command {
	return &rungrad.Command{Use: "init", Short: "Record your decisions and prepare draft CRA documents",
		Long:     "Show the detected product and dependencies, then ask for your decisions.\nWrite cra.yml, scan dependencies and create missing draft documents.\nUnknown answers stay unknown. An answers file is a partial cra.yml; null suppresses a question.\nWith --no-prompt, omitted maker decisions stay unknown. Detection still supplies product facts.\nLookups send package names, versions and advisory ids to OSV.dev and download CISA KEV.\nFinish with the evidence status, even after incomplete lookups. Exit 10 for policy failures, 11 for incomplete or stale evidence; otherwise 0.\nRefuse to replace cra.yml; use scan, docs and check after setup.\nUse --dry-run to preview without writes, lookups or Git subprocesses.",
		Examples: []string{"conformline init", "conformline init --answers answers.yml --no-prompt --release dist/plugin.zip", "conformline init --offline --no-prompt"},
		Mutates:  true, OutputModes: []string{rungrad.OutputModeHuman, rungrad.OutputModeJSON}, Args: cobra.NoArgs,
		Configure: func(cmd *cobra.Command) {
			cmd.Flags().String("answers", "", "Partial cra.yml with your interview answers")
			cmd.Flags().String("release", "", "Release ZIP or folder, relative to --dir")
			cmd.Flags().Bool("offline", false, "Skip vulnerability lookups and mark the scan incomplete")
		},
		Run: func(f *rungrad.Factory, cmd *cobra.Command, _ []string) error {
			result, err := initialize(f, cmd, *dir, client, nil)
			if err != nil {
				return err
			}
			scan, docs, checked := result.Scan, result.Documents, result.Status
			if err = f.WriteResult(result, func(w io.Writer) {
				if f.DryRun() {
					fmt.Fprintln(w, "DRY RUN: would write cra.yml")
				} else {
					fmt.Fprintln(w, "Created cra.yml")
				}
				renderScan(w, scan)
				renderDocuments(w, docs)
				status.Terminal(w, checked, status.OutputWidth(f.Stdout))
			}); err != nil {
				return err
			}
			if checked.ExitCode != 0 {
				return &checkExit{checked.ExitCode}
			}
			return nil
		}}
}

func initialize(f *rungrad.Factory, cmd *cobra.Command, dir string, client *vulns.Client, supplied *profile.Profile) (initResult, error) {
	path := filepath.Join(dir, "cra.yml")
	if _, err := os.Lstat(path); err == nil {
		return initResult{}, rungrad.NewError(1, "cra.yml already exists; use conformline scan, conformline docs and conformline check")
	} else if !os.IsNotExist(err) {
		return initResult{}, rungrad.NewError(2, "Cannot inspect cra.yml; check project permissions")
	}
	p := supplied
	if p == nil {
		p = &profile.Profile{Version: 1, Role: profile.Role{Answer: "unknown"}, Classification: profile.Classification{Answer: "unknown"}}
		answers, _ := cmd.Flags().GetString("answers")
		if answers != "" {
			var err error
			p, err = profile.Load(answers)
			if err != nil {
				return initResult{}, rungrad.NewError(1, "Cannot read --answers: "+safeError(err))
			}
		}
	}
	product, err := detect.Detect(dir)
	if err != nil {
		return initResult{}, rungrad.NewError(2, err.Error())
	}
	if p.Product.Version != nil {
		product.Version = p.Product.Version
	}
	var release *string
	if cmd.Flags().Changed("release") {
		value, _ := cmd.Flags().GetString("release")
		release = &value
	}
	inv, err := inventory.BuildWithOptions(dir, product, inventory.Options{Release: release, Profile: p})
	if err != nil {
		return initResult{}, rungrad.NewError(2, err.Error())
	}
	// Only found facts are printed before the interview; scan results come afterwards.
	if f.Flags == nil || (!f.Flags.JSON && f.Flags.JQ == "" && f.Flags.Template == "") {
		renderFound(f.Stderr, Report{Inventory: inv})
	}
	if !p.HasAnswer("product.name") {
		p.Product.Name = product.Name
	}
	if !p.HasAnswer("product.type") {
		p.Product.Type = detect.String(product.Type)
	}
	if !p.HasAnswer("product.description") {
		p.Product.Description = product.Description
	}
	if release == nil && !p.HasAnswer("product.release") {
		release = inv.Release
	}
	if err = conductInterview(f, p, dir, product, release); err != nil {
		return initResult{}, err
	}
	if !f.DryRun() && (p.Role.DecidedBy == nil && !p.HasAnswer("role.decided_by") || p.Classification.DecidedBy == nil && !p.HasAnswer("classification.decided_by")) {
		command := exec.CommandContext(cmd.Context(), "git", "-C", dir, "config", "user.name")
		name, _ := command.Output()
		if !p.HasAnswer("role.decided_by") {
			p.Role.DecidedBy = detect.String(string(bytes.TrimSpace(name)))
		}
		if !p.HasAnswer("classification.decided_by") {
			p.Classification.DecidedBy = detect.String(string(bytes.TrimSpace(name)))
		}
	}
	p.AddGuidance()
	if !f.DryRun() {
		if err = p.Save(path); err != nil {
			if _, ok := err.(*os.PathError); ok {
				return initResult{}, rungrad.NewError(2, "Cannot write cra.yml; check project permissions and free space")
			}
			return initResult{}, rungrad.NewError(1, "Cannot save cra.yml: "+safeError(err))
		}
	}
	scan, err := scanProject(f, cmd, dir, client, p)
	if err != nil {
		return initResult{}, err
	}
	docs, err := documents.Generate(dir, p, time.Now().UTC(), f.DryRun())
	if err != nil {
		return initResult{}, rungrad.NewError(2, err.Error())
	}
	checked, err := evaluateStatus(dir, p, false, f.DryRun())
	if err != nil {
		return initResult{}, err
	}
	result := initResult{Profile: "cra.yml", Scan: scan, Documents: docs, Status: checked}
	return result, nil
}

func docsCommand(dir *string) *rungrad.Command {
	return &rungrad.Command{Use: "docs", Short: "Create missing draft documents and refresh the index",
		Long:     "Create missing documents from cra.yml and saved reports.\nPreserve every existing evidence document, including SECURITY.md.\nReplace the generated cra/README.md index on each run.\nFor not-in-scope, write only the index and preserve existing documents.\nUse --dry-run to list changes without writing files.",
		Examples: []string{"conformline docs", "conformline docs --dry-run --json"}, Mutates: true, OutputModes: []string{rungrad.OutputModeHuman, rungrad.OutputModeJSON}, Args: cobra.NoArgs,
		Run: func(f *rungrad.Factory, _ *cobra.Command, _ []string) error {
			p, err := profile.Load(filepath.Join(*dir, "cra.yml"))
			if os.IsNotExist(err) {
				return rungrad.NewError(1, "Run conformline init first; docs needs cra.yml")
			}
			if err != nil {
				return rungrad.NewError(1, "Cannot load cra.yml: "+safeError(err))
			}
			r, err := documents.Generate(*dir, p, time.Now().UTC(), f.DryRun())
			if err != nil {
				return rungrad.NewError(2, err.Error())
			}
			checked, err := status.Evaluate(*dir, p, time.Now().UTC(), false)
			if err != nil {
				return rungrad.NewError(2, err.Error())
			}
			if err = documents.WriteIndex(*dir, p, time.Now().UTC(), checked.Next, f.DryRun()); err != nil {
				return rungrad.NewError(2, err.Error())
			}
			return f.WriteResult(r, func(w io.Writer) { renderDocuments(w, r) })
		}}
}
func renderDocuments(w io.Writer, r documents.Result) {
	for _, file := range r.Created {
		if r.DryRun {
			fmt.Fprintln(w, "Would create "+file)
		} else {
			fmt.Fprintln(w, "Created "+file)
		}
	}
	for _, file := range r.Existing {
		fmt.Fprintln(w, "Existing "+file+" (kept)")
	}
	if r.DryRun {
		fmt.Fprintln(w, "Would refresh cra/README.md")
	} else {
		fmt.Fprintln(w, "Refreshed cra/README.md")
	}
	if r.Message != "" {
		fmt.Fprintln(w, r.Message)
	}
}
