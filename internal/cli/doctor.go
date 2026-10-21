package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vincentsch/fendkit/internal/detect"
	"github.com/vincentsch/fendkit/internal/inventory"
	"github.com/vincentsch/fendkit/internal/profile"
	"github.com/vincentsch/fendkit/internal/version"
	"github.com/vincentsch/fendkit/internal/vulns"
	"github.com/vincentsch/rungrad"
)

type doctorCheck struct {
	Level   string `json:"level"`
	Name    string `json:"name"`
	Message string `json:"message"`
	Fix     string `json:"fix"`
}
type doctorResult struct {
	Checks []doctorCheck `json:"checks"`
}

func doctorCommand(dir *string, client *vulns.Client) *rungrad.Command {
	return &rungrad.Command{Use: "doctor", Short: "Check project setup and advisory connections", Long: "Check the repository, ecosystems, lockfile coverage, release and cra.yml.\nCheck OSV.dev and CISA KEV reachability without sending project information.\nShow ok, information, warning or problem for each check, with a next action.\nMissing cra.yml is information; unresolved runtime versions are coverage warnings.\nMake no repairs or file changes. Exit 2 when any problem exists, otherwise 0.", Examples: []string{"fendkit doctor", "fendkit doctor --dir ./my-plugin --json"}, Args: cobra.NoArgs, OutputModes: []string{rungrad.OutputModeHuman, rungrad.OutputModeJSON}, Run: func(f *rungrad.Factory, cmd *cobra.Command, _ []string) error {
		r := diagnose(cmd.Context(), *dir, client)
		if err := f.WriteResult(r, func(w io.Writer) {
			for _, check := range r.Checks {
				fmt.Fprintf(w, "%s  %s: %s\n  Fix: %s\n", check.Level, check.Name, check.Message, check.Fix)
			}
		}); err != nil {
			return err
		}
		for _, check := range r.Checks {
			if check.Level == "problem" {
				return &checkExit{2}
			}
		}
		return nil
	}}
}

func diagnose(ctx context.Context, root string, client *vulns.Client) doctorResult {
	r := doctorResult{Checks: []doctorCheck{}}
	add := func(level, name, message, fix string) {
		r.Checks = append(r.Checks, doctorCheck{level, name, message, fix})
	}
	product, err := detect.Detect(root)
	if err != nil {
		add("problem", "Repository", err.Error(), "Check --dir and correct the named files or permissions.")
	} else {
		add("ok", "Repository", "Project files are readable.", "Use --dir to check another project.")
		ecosystems := []string{}
		for _, pair := range []struct{ file, name string }{{"composer.json", "Composer"}, {"package.json", "npm"}, {"composer.lock", "Composer"}, {"package-lock.json", "npm"}, {"npm-shrinkwrap.json", "npm"}, {"pnpm-lock.yaml", "npm (pnpm)"}, {"yarn.lock", "npm (Yarn)"}} {
			if _, e := os.Stat(filepath.Join(root, pair.file)); e == nil && !slices.Contains(ecosystems, pair.name) {
				ecosystems = append(ecosystems, pair.name)
			}
		}
		if len(ecosystems) == 0 {
			add("information", "Ecosystems", "No Composer or npm metadata found.", "Scan bundled JavaScript or add manual components in cra.yml.")
		} else {
			add("ok", "Ecosystems", strings.Join(ecosystems, ", "), "Keep lockfiles with the project to record installed versions.")
		}
		p, loadErr := profile.Load(filepath.Join(root, "cra.yml"))
		switch {
		case os.IsNotExist(loadErr):
			add("information", "cra.yml", "Not created yet.", "Run fendkit init.")
		case loadErr != nil:
			add("problem", "cra.yml", safeError(loadErr), "Correct cra.yml, then run fendkit doctor.")
			p = nil
		default:
			add("ok", "cra.yml", "Profile is valid.", "Use fendkit check to review evidence and decisions.")
		}
		if p != nil && p.Product.Version != nil {
			product.Version = p.Product.Version
		}
		inv, buildErr := inventory.BuildWithOptions(root, product, inventory.Options{Profile: p})
		if buildErr != nil {
			add("problem", "Inventory and release", buildErr.Error(), "Correct the named file or product.release, then run fendkit doctor.")
		} else {
			for _, note := range inv.Product.Notes {
				level := "warning"
				if strings.HasPrefix(note, "Several release ZIPs match:") {
					level = "problem"
				}
				add(level, "Product and release", note, "Align product metadata and set product.release to the intended ZIP or folder.")
			}
			if inv.Release == nil {
				add("warning", "Release", "No release artifact selected.", "Set product.release in cra.yml to the release ZIP or folder.")
			} else {
				add("ok", "Release", *inv.Release, "Keep this artifact available; scan uses it to confirm what ships.")
			}
			if len(inv.CoverageGaps) == 0 {
				add("ok", "Dependency coverage", "No inventory coverage gaps found.", "Run fendkit scan to check known vulnerabilities.")
			}
			for _, gap := range inv.CoverageGaps {
				add("warning", "Dependency coverage", gap.File+": "+gap.Message, "Supply the named version evidence or a manual component in cra.yml, then run fendkit scan and review vulnerability coverage.")
			}
		}
	}
	for _, endpoint := range []struct{ name, method, url, body string }{{"OSV.dev", http.MethodPost, strings.TrimRight(client.OSV, "/") + "/v1/querybatch", `{"queries":[]}`}, {"CISA KEV", http.MethodGet, client.KEV, ""}} {
		err := probe(ctx, client.HTTP, endpoint.method, endpoint.url, endpoint.body)
		if err != nil {
			add("problem", endpoint.name, err.Error(), "Check your connection and proxy settings, then run fendkit doctor; use scan --offline meanwhile.")
		} else {
			add("ok", endpoint.name, "Endpoint is reachable.", "Run fendkit scan for current advisory data.")
		}
	}
	return r
}

func probe(ctx context.Context, client *http.Client, method, endpoint, body string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("cannot create connection check")
	}
	req.Header.Set("User-Agent", "fendkit/"+version.Version)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed or timed out (5 s limit)")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("endpoint returned HTTP %d", response.StatusCode)
	}
	return nil
}
