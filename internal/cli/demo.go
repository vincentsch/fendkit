package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vincentsch/conformline/internal/demo"
	"github.com/vincentsch/conformline/internal/inventory"
	"github.com/vincentsch/conformline/internal/profile"
	"github.com/vincentsch/conformline/internal/status"
	"github.com/vincentsch/conformline/internal/vulns"
	"github.com/vincentsch/rungrad"
)

type demoResult struct {
	Init          *initResult `json:"init,omitempty"`
	Directory     string      `json:"directory"`
	StatusPath    string      `json:"status_path"`
	DocumentsPath string      `json:"documents_path"`
	SBOMPath      string      `json:"sbom_path"`
	Commands      []string    `json:"commands"`
	DryRun        bool        `json:"dry_run"`
	LookupHint    string      `json:"lookup_hint,omitempty"`
}

func demoCommand(client *vulns.Client) *rungrad.Command {
	return &rungrad.Command{Use: "demo", Short: "Try Conformline on the bundled example plugin", Long: "Copy Acme Booking and its release ZIP into ./conformline-demo/ or --out.\nRefuse a non-empty output folder before writing anything.\nRun init, scan, docs and check with bundled demo answers, without prompts or Git.\nLookups send package names, versions and advisory ids to OSV.dev and download CISA KEV.\nUse --offline to skip all network requests. Failed lookups still produce reports.\nExit with the final check code: 10 for policy failures, 11 for incomplete evidence, otherwise 0.\nUse --dry-run to preview without copying files or making network requests.", Examples: []string{"conformline demo", "conformline demo --offline --out ./example"}, Mutates: true, Args: cobra.NoArgs, OutputModes: []string{rungrad.OutputModeHuman, rungrad.OutputModeJSON}, Configure: func(cmd *cobra.Command) {
		cmd.Flags().String("out", "./conformline-demo", "Empty destination folder for the example and release ZIP")
		cmd.Flags().Bool("offline", false, "Skip vulnerability lookups and mark the scan incomplete")
	}, Run: func(f *rungrad.Factory, cmd *cobra.Command, _ []string) error {
		out, _ := cmd.Flags().GetString("out")
		if strings.TrimSpace(out) == "" {
			return rungrad.NewError(1, "--out is empty; choose an empty destination folder")
		}
		if err := demo.ValidateOutput(out); err != nil {
			return rungrad.NewError(1, err.Error())
		}
		root := filepath.Join(out, "acme-booking")
		displayRoot := root
		if filepath.IsAbs(root) {
			cwd, err := os.Getwd()
			if err != nil {
				return rungrad.NewError(2, "Cannot resolve --out; run from a readable working directory")
			}
			displayRoot = inventory.RelativeOrAbsolute(cwd, root)
		}
		r := demoResult{Directory: filepath.ToSlash(displayRoot), StatusPath: filepath.ToSlash(filepath.Join(displayRoot, "cra/reports/status.html")), DocumentsPath: filepath.ToSlash(filepath.Join(displayRoot, "cra")), SBOMPath: filepath.ToSlash(filepath.Join(displayRoot, "cra/reports/sbom.cdx.json")), DryRun: f.DryRun()}
		if f.DryRun() {
			return f.WriteResult(r, func(w io.Writer) {
				fmt.Fprintf(w, "DRY RUN: would copy the example to %s and run init, scan, docs and check; no changes were made\n", r.Directory)
			})
		}
		if err := demo.Copy(out); err != nil {
			return rungrad.NewError(2, "Cannot copy the example; check --out permissions and free space")
		}
		p, err := profile.Parse(demo.Answers(time.Now()))
		if err != nil {
			return err
		}
		// The demo supplies decisions itself and must never ask a question.
		demoFactory := *f
		flags := *f.Flags
		flags.NoPrompt = true
		demoFactory.Flags = &flags
		offline, _ := cmd.Flags().GetBool("offline")
		initCmd := &cobra.Command{}
		initCmd.Flags().Bool("offline", offline, "")
		initCmd.Flags().String("release", "", "")
		if err = initCmd.Flags().Set("release", "../dist/acme-booking-2.3.1.zip"); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 25*time.Second)
		defer cancel()
		initCmd.SetContext(ctx)
		result, err := initialize(&demoFactory, initCmd, root, client, p)
		if err != nil {
			return err
		}
		r.Init = &result
		if !result.Scan.Complete && !result.Scan.Offline {
			r.LookupHint = "Lookups did not finish. Try conformline demo --offline --out <another-empty-folder>."
		}
		data, err := os.ReadFile(filepath.Join(root, "cra/reports/vulnerabilities.json"))
		var findings vulns.Report
		if err == nil {
			err = json.Unmarshal(data, &findings)
		}
		if err != nil {
			return rungrad.NewError(2, "Cannot read demo findings; run conformline scan in the example folder")
		}
		r.Commands = demoCommands(r.Directory, findings.Findings)
		if err = f.WriteResult(r, func(w io.Writer) {
			renderScan(w, result.Scan)
			renderDocuments(w, result.Documents)
			status.Terminal(w, result.Status, status.OutputWidth(f.Stdout))
			if r.LookupHint != "" {
				fmt.Fprintln(w, r.LookupHint)
			}
			fmt.Fprintf(w, "\nOpen status: %s\nDraft documents: %s/\nSBOM: %s\n\nTry next:\n", r.StatusPath, r.DocumentsPath, r.SBOMPath)
			for _, command := range r.Commands {
				fmt.Fprintln(w, "  "+command)
			}
		}); err != nil {
			return err
		}
		if result.Status.ExitCode != 0 {
			return &checkExit{result.Status.ExitCode}
		}
		return nil
	}}
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func demoCommands(root string, findings []vulns.Finding) []string {
	target := " --dir " + shellQuote(root)
	first := "conformline scan" + target
	if len(findings) > 0 {
		finding := findings[0]
		first = "conformline triage " + shellQuote(finding.Advisories[0].ID) + " --status under_investigation --reason \"Demo exercise only\" --component " + shellQuote(finding.Component.PURL) + target
	}
	return []string{first, "conformline incident new --type exploited-vulnerability --title \"Demo vulnerability\"" + target, "conformline check" + target}
}
