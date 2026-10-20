package cli

import (
	"bufio"
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
	"github.com/vincentsch/conformline/internal/profile"
	"github.com/vincentsch/conformline/internal/vulns"
	"github.com/vincentsch/rungrad"
)

// TextInput shares one buffered reader across the later interview's questions.
type TextInput struct{ reader *bufio.Reader }

func (t *TextInput) Ask(f *rungrad.Factory, prompt string) (string, error) {
	if !f.CanPrompt() {
		return "", rungrad.NewError(1, "Cannot ask for text in JSON or non-interactive mode; set the required field in cra.yml")
	}
	if t.reader == nil {
		t.reader = bufio.NewReader(f.Stdin)
	}
	fmt.Fprint(f.Stderr, prompt+": ")
	line, err := t.reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", rungrad.NewError(2, "Cannot read the answer; set the required field in cra.yml")
	}
	return strings.TrimSpace(line), nil
}
func triageCommand(dir *string) *rungrad.Command {
	return &rungrad.Command{Use: "triage <advisory-id>", Short: "Record a decision and export product-specific VEX", Long: "Select any advisory id or alias from the saved vulnerabilities report.\nRequires cra.yml and manufacturer.name. No network requests are made.\nUse --component with the exact versioned purl printed in vulnerabilities.md when several components match.\nEvery status requires --reason. For affected, describe the intended response.\nnot_affected also requires an OpenVEX --justification.\nA new decision replaces the current decision for this advisory group and component version.\nUse --dry-run to preview the decision without writing files.", Examples: []string{"conformline triage GHSA-f2wf-25xc-69c9 --status under_investigation --reason 'Reviewing product usage'", "conformline triage GHSA-f2wf-25xc-69c9 --status not_affected --justification vulnerable_code_not_in_execute_path --reason 'The product does not use the affected code path'"}, Mutates: true, OutputModes: []string{rungrad.OutputModeHuman, rungrad.OutputModeJSON}, Args: cobra.ExactArgs(1), Configure: func(cmd *cobra.Command) {
		cmd.Flags().String("status", "", "affected, not_affected, fixed, or under_investigation")
		cmd.Flags().String("reason", "", "Reason for the decision; for affected, describe the intended response (required)")
		cmd.Flags().String("component", "", "Exact component purl with version from vulnerabilities.md")
		cmd.Flags().String("justification", "", "Required for not_affected: component_not_present, vulnerable_code_not_present, vulnerable_code_not_in_execute_path, vulnerable_code_cannot_be_controlled_by_adversary, inline_mitigations_already_exist")
	}, Run: func(f *rungrad.Factory, cmd *cobra.Command, args []string) error {
		get := func(name string) string { s, _ := cmd.Flags().GetString(name); return s }
		status, reason, justification, component := get("status"), get("reason"), get("justification"), get("component")
		if strings.TrimSpace(reason) == "" {
			return rungrad.NewError(1, "--reason is required for every status; describe your decision (and intended response for affected)")
		}
		if !slices.Contains([]string{"affected", "not_affected", "fixed", "under_investigation"}, status) {
			return rungrad.NewError(1, "--status must be affected, not_affected, fixed, or under_investigation")
		}
		prof, err := profile.Load(filepath.Join(*dir, "cra.yml"))
		if os.IsNotExist(err) {
			return rungrad.NewError(1, "Run `conformline init` first; triage needs an existing cra.yml")
		}
		if err != nil {
			return rungrad.NewError(1, "Cannot load cra.yml: "+safeError(err))
		}
		b, err := os.ReadFile(filepath.Join(*dir, "cra/reports/vulnerabilities.json"))
		if err != nil {
			return rungrad.NewError(1, "No readable saved vulnerability report; run conformline scan first")
		}
		var r vulns.Report
		if json.Unmarshal(b, &r) != nil || r.ScanID == "" || r.ProductPURL == "" {
			return rungrad.NewError(1, "Invalid saved vulnerability report; run conformline scan again")
		}
		matches := []int{}
		choices := []string{}
		for i, finding := range r.Findings {
			if slices.Contains(finding.IDs, args[0]) {
				choices = append(choices, finding.Component.PURL)
				if component == "" || component == finding.Component.PURL {
					matches = append(matches, i)
				}
			}
		}
		if len(matches) == 0 {
			return rungrad.NewError(5, "No saved finding matches this advisory and component; check vulnerabilities.md or run conformline scan")
		}
		if len(matches) > 1 {
			return rungrad.NewError(1, "This advisory matches several components; pass --component with one of: "+strings.Join(choices, ", "))
		}
		finding := r.Findings[matches[0]]
		decision := profile.Triage{Advisory: detect.String(finding.Advisories[0].ID), Component: detect.String(finding.Component.PURL), Status: &status, Justification: detect.String(justification), Reason: &reason, DecidedOn: detect.String(time.Now().UTC().Format("2006-01-02"))}
		if err = profile.ValidateTriage(decision); err != nil {
			return rungrad.NewError(1, err.Error())
		}
		if prof.Manufacturer.Name == nil || strings.TrimSpace(*prof.Manufacturer.Name) == "" {
			if f.DryRun() {
				return rungrad.NewError(1, "Set manufacturer.name in cra.yml before exporting VEX")
			}
			if !f.CanPrompt() {
				return rungrad.NewError(1, "Set manufacturer.name in cra.yml; this command cannot prompt in JSON or non-interactive mode")
			}
			var input TextInput
			name, err := input.Ask(f, "Manufacturer name for the VEX author")
			if err != nil {
				return err
			}
			if name == "" {
				return rungrad.NewError(1, "Set manufacturer.name in cra.yml; a VEX author is required")
			}
			prof.Manufacturer.Name = &name
		}
		kept := []profile.Triage{}
		replaced := false
		for _, old := range prof.Triage {
			if old.Component != nil && old.Advisory != nil && *old.Component == finding.Component.PURL && slices.Contains(finding.IDs, *old.Advisory) {
				if !replaced {
					kept = append(kept, decision)
					replaced = true
				}
				continue
			}
			kept = append(kept, old)
		}
		if !replaced {
			kept = append(kept, decision)
		}
		prof.Triage = kept
		vulns.Apply(&r, prof)
		if _, err = vulns.VEX(r, prof); err != nil {
			return rungrad.NewError(1, err.Error())
		}
		if !f.DryRun() {
			if err = prof.Save(filepath.Join(*dir, "cra.yml")); err != nil {
				return rungrad.NewError(2, "Cannot save cra.yml: "+safeError(err))
			}
			if err = vulns.Write(*dir, r, prof); err != nil {
				return rungrad.NewError(2, err.Error())
			}
		}
		return f.WriteResult(struct {
			DryRun   bool           `json:"dry_run"`
			ScanID   string         `json:"scan_id"`
			Decision profile.Triage `json:"decision"`
		}{f.DryRun(), r.ScanID, decision}, func(w io.Writer) {
			if f.DryRun() {
				fmt.Fprint(w, "DRY RUN: would record ")
			} else {
				fmt.Fprint(w, "Recorded ")
			}
			fmt.Fprintf(w, "%s for %s in %s.\n", status, args[0], finding.Component.PURL)
			if f.DryRun() {
				fmt.Fprintln(w, "Would rewrite vulnerabilities.json, vulnerabilities.md and vex.openvex.json; no changes were made.")
			} else {
				fmt.Fprintln(w, "Updated cra.yml and the saved vulnerability reports without network access.")
			}
		})
	}}
}
