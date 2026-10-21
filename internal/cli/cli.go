package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vincentsch/fendkit/internal/detect"
	"github.com/vincentsch/fendkit/internal/inventory"
	"github.com/vincentsch/fendkit/internal/profile"
	"github.com/vincentsch/fendkit/internal/sbom"
	"github.com/vincentsch/fendkit/internal/version"
	"github.com/vincentsch/fendkit/internal/vulns"
	"github.com/vincentsch/rungrad"
)

type Report struct {
	ScanID            string    `json:"scan_id"`
	ScannedAt         time.Time `json:"scanned_at"`
	ProductVersion    *string   `json:"product_version"`
	InventoryDigest   string    `json:"inventory_digest"`
	Complete          bool      `json:"complete"`
	IncompleteReasons []string  `json:"incomplete_reasons"`
	Offline           bool      `json:"offline"`
	DryRun            bool      `json:"dry_run"`
	Output            string    `json:"output"`
	FindingCount      int       `json:"finding_count"`
	inventory.Inventory
}

func New() *rungrad.App { return newApp(vulns.NewClient()) }

func newApp(client *vulns.Client) *rungrad.App {
	app := rungrad.New(rungrad.AppConfig{Name: "fendkit", Short: "Prepare your Cyber Resilience Act evidence", Long: "Find your product and its dependencies, and record what still needs review.", Version: version.Version, ErrorPolicy: &rungrad.ErrorPolicy{
		Render: func(ctx rungrad.ErrorContext) error {
			var pending *incomplete
			var checked *checkExit
			if errors.As(ctx.Err, &pending) || errors.As(ctx.Err, &checked) {
				return nil
			}
			if ctx.MachineOutput {
				b, e := json.Marshal(map[string]any{"error": ctx.Err.Error(), "exit_code": ctx.ExitCode})
				if e != nil {
					return e
				}
				_, e = ctx.Stderr.Write(ctx.RedactJSON(append(b, '\n')))
				return e
			}
			_, e := fmt.Fprintln(ctx.Stderr, "Error:", ctx.RedactString(ctx.Err.Error()))
			return e
		},
	}})
	app.Root().SetVersionTemplate(fmt.Sprintf("fendkit {{.Version}} (commit %s, %s)\n", version.Commit, runtime.Version()))
	dir := "."
	app.Root().PersistentFlags().StringVar(&dir, "dir", ".", "Project root")
	app.AddCommand(&rungrad.Command{Use: "scan", Short: "Find dependencies and look up known vulnerabilities", Long: "Read WordPress headers, Composer and npm metadata, bundled JavaScript, and release ZIPs or folders.\nWrite inventory.json, sbom.cdx.json, vulnerabilities.json and vulnerabilities.md under cra/reports/.\nExport vex.openvex.json when saved triage matches findings.\nLookups send package names, versions and advisory ids to OSV.dev, and download CISA KEV.\nPackage names and versions can reveal product information.\nExit 0 for complete lookups, 11 for offline or failed lookups.\nApply product settings and manual components from cra.yml.\nA release flag overrides product.release; relative paths start at --dir.\nReject conflicting detected product identities or versions before replacing reports.\nMissing comparable identity metadata is reported as unverified.\nChanging the saved release setting makes earlier evidence stale.\nWithout either, use a single dist/ or build/ ZIP containing the product version.\nDevelopment packages bundled without recognizable evidence need a manual shipped correction or a move to dependencies.\nUse --dry-run to preview the result without writing files.", Examples: []string{"fendkit scan", "fendkit scan --offline", "fendkit scan --offline --dir ./my-plugin --json", "fendkit scan --offline --dry-run"}, OutputModes: []string{rungrad.OutputModeHuman, rungrad.OutputModeJSON}, Mutates: true, Args: cobra.NoArgs, Configure: func(cmd *cobra.Command) {
		cmd.Flags().String("release", "", "Release ZIP or folder, relative to --dir (overrides product.release)")
		cmd.Flags().Bool("offline", false, "Skip vulnerability lookups and mark the scan incomplete")
	}, Run: func(f *rungrad.Factory, cmd *cobra.Command, args []string) error {
		r, err := scanProject(f, cmd, dir, client, nil)
		if err != nil {
			return err
		}
		if err = f.WriteResult(r, func(w io.Writer) { render(w, r) }); err != nil {
			return err
		}
		if !r.Complete {
			return &incomplete{}
		}
		return nil
	}})
	app.AddCommand(triageCommand(&dir))
	app.AddCommand(initCommand(&dir, client))
	app.AddCommand(docsCommand(&dir))
	app.AddCommand(checkCommand(&dir))
	app.AddCommand(incidentCommand(&dir, time.Now))
	app.AddCommand(doctorCommand(&dir, client))
	app.AddCommand(demoCommand(client))
	return app
}

// A scan result has already been printed; incompleteness is an exit status.
type incomplete struct{}

func (*incomplete) Error() string { return "Vulnerability scan incomplete" }
func (*incomplete) ExitCode() int { return 11 }
func safeError(e error) string {
	if _, ok := e.(*os.PathError); ok {
		return "file cannot be read; check its permissions"
	}
	return e.Error()
}
func writeReport(root string, r Report, prof *profile.Profile) error {
	dir := filepath.Join(root, "cra", "reports")
	if e := os.MkdirAll(dir, 0755); e != nil {
		return fmt.Errorf("cannot create cra/reports; check project permissions")
	}
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
	}
	sbomFile, e := os.CreateTemp(dir, ".sbom-*.json")
	if e != nil {
		return fmt.Errorf("cannot write sbom.cdx.json; check cra/reports permissions")
	}
	defer os.Remove(sbomFile.Name())
	bom := sbom.New(r.Inventory, prof, sbom.Provenance{ScanID: r.ScanID, ScannedAt: r.ScannedAt, InventoryDigest: r.InventoryDigest, Complete: r.Complete, Offline: r.Offline, IncompleteReasons: r.IncompleteReasons}, version.Version)
	e = sbom.Write(sbomFile, bom)
	closeErr := sbomFile.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return fmt.Errorf("cannot encode sbom.cdx.json: %w", e)
	}
	b = append(b, '\n')
	f, e := os.CreateTemp(dir, ".inventory-*.json")
	if e != nil {
		return fmt.Errorf("cannot write inventory.json; check cra/reports permissions")
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(b); e == nil {
		e = f.Close()
	} else {
		f.Close()
	}
	if e == nil {
		e = os.Rename(name, filepath.Join(dir, "inventory.json"))
	}
	if e != nil {
		return fmt.Errorf("cannot replace inventory.json; check cra/reports permissions")
	}
	if e = os.Rename(sbomFile.Name(), filepath.Join(dir, "sbom.cdx.json")); e != nil {
		return fmt.Errorf("cannot replace sbom.cdx.json; check cra/reports permissions")
	}
	return nil
}
func render(w io.Writer, r Report) {
	renderFound(w, r)
	renderScan(w, r)
}
func renderFound(w io.Writer, r Report) {
	labels := map[string]string{"wordpress-plugin": "WordPress plugin", "wordpress-theme": "WordPress theme", "composer-package": "Composer package", "npm-package": "npm package", "other": "Product", "application": "Application"}
	name := "unknown"
	if r.Product.Name != nil {
		name = *r.Product.Name
	}
	version := "version unknown"
	if r.Product.Version != nil {
		version = *r.Product.Version
	}
	fmt.Fprintf(w, "Found\n  %-18s %s %s", labels[r.Product.Type], name, version)
	if len(r.Product.Evidence) > 0 {
		fmt.Fprintf(w, " (%s)", strings.Join(r.Product.Evidence, ", "))
	}
	fmt.Fprintln(w)
	for _, eco := range []string{"composer", "npm"} {
		shipped, dev, excluded, unknown := 0, 0, 0, 0
		for _, c := range r.Components {
			if c.Ecosystem != eco || strings.Contains(c.Source.Method, "bundled JavaScript") {
				continue
			}
			if c.Shipped != nil && *c.Shipped {
				shipped++
			} else if c.Shipped == nil {
				unknown++
			} else if c.Development {
				dev++
			} else {
				excluded++
			}
		}
		label := "Composer"
		if eco == "npm" {
			label = "npm"
		}
		if eco == "npm" && shipped == 0 && unknown == 0 && excluded == 0 && dev > 0 {
			fmt.Fprintf(w, "  %-18s %d build tools (not shipped)\n", label, dev)
			continue
		}
		fmt.Fprintf(w, "  %-18s %d packages to ship, %d for development only (not shipped)", label, shipped, dev)
		if excluded > 0 {
			fmt.Fprintf(w, ", %d absent from release (not shipped)", excluded)
		}
		if unknown > 0 {
			if eco == "npm" {
				fmt.Fprintf(w, ", %d shipped: unknown (may be compiled into your bundles)", unknown)
			} else {
				fmt.Fprintf(w, ", %d possibly shipped (package evidence needs review)", unknown)
			}
		}
		fmt.Fprintln(w)
	}
	renderBundled(w, r.Components)
	release := "none; set product.release to confirm what ships"
	if r.Release != nil {
		release = *r.Release
	}
	fmt.Fprintln(w, "  Release file       "+release)
	fmt.Fprintln(w, "  Note               Development packages compiled into bundles need a manual shipped correction or a move to dependencies")
	for _, note := range r.Product.Notes {
		fmt.Fprintln(w, "  Note               "+note)
	}
	for _, gap := range r.CoverageGaps {
		fmt.Fprintln(w, "  Coverage gap       "+gap.Message)
	}
	if r.Product.Version == nil {
		fmt.Fprintln(w, "  Next               Set product.version in cra.yml; the product version is unknown")
	}
}
func renderScan(w io.Writer, r Report) {
	if r.DryRun {
		fmt.Fprintln(w, "\nDRY RUN: would write "+r.Output+" and cra/reports/sbom.cdx.json, vulnerabilities.json, vulnerabilities.md and matching VEX; no changes were made")
	} else {
		fmt.Fprintln(w, "\nInventory: "+r.Output+"\nSBOM: cra/reports/sbom.cdx.json")
	}
	if r.Complete {
		fmt.Fprintf(w, "%d advisory groups found.\n", r.FindingCount)
		fmt.Fprintln(w, "Vulnerability lookups complete. Review cra/reports/vulnerabilities.md.")
	} else {
		for _, reason := range r.IncompleteReasons {
			fmt.Fprintln(w, "Scan incomplete: "+reason)
		}
	}
}

func renderBundled(w io.Writer, components []inventory.Component) {
	type group struct {
		directory, state string
		unlisted         bool
		libraries        []string
	}
	groups := []group{}
	for _, c := range components {
		directory := ""
		unlisted := true
		for _, ev := range c.Evidence {
			if strings.Contains(ev.Method, "bundled JavaScript") {
				if directory == "" {
					directory = path.Dir(ev.Path) + "/"
				}
			} else {
				unlisted = false
			}
		}
		if directory == "" {
			continue
		}
		version := "version unknown"
		if c.Version != nil {
			version = *c.Version
		}
		state := "shipped: unknown"
		if c.Shipped != nil {
			if *c.Shipped {
				state = ""
			} else {
				state = "not shipped"
			}
		}
		index := -1
		for i, g := range groups {
			if g.directory == directory && g.state == state && g.unlisted == unlisted {
				index = i
				break
			}
		}
		if index < 0 {
			index = len(groups)
			groups = append(groups, group{directory: directory, state: state, unlisted: unlisted})
		}
		groups[index].libraries = append(groups[index].libraries, inventory.LibraryDisplayName(c.Name)+" "+version)
	}
	if len(groups) == 0 {
		fmt.Fprintln(w, "  Bundled JS         none detected")
	}
	for _, g := range groups {
		label := "libraries"
		if len(g.libraries) == 1 {
			label = "library"
		}
		fmt.Fprintf(w, "  Bundled JS         %d %s in %s", len(g.libraries), label, g.directory)
		if g.unlisted {
			fmt.Fprint(w, " not listed anywhere")
		}
		if g.state != "" {
			fmt.Fprintf(w, " (%s)", g.state)
		}
		fmt.Fprintln(w, ":")
		fmt.Fprintln(w, "                     "+strings.Join(g.libraries, ", "))
	}
	for _, c := range components {
		if c.Note != "" {
			fmt.Fprintln(w, "  Note               "+c.Note)
		}
	}
}

func scanProject(f *rungrad.Factory, cmd *cobra.Command, dir string, client *vulns.Client, supplied *profile.Profile) (Report, error) {
	p, e := detect.Detect(dir)
	if e != nil {
		return Report{}, rungrad.NewError(2, e.Error())
	}
	prof := supplied
	var eLoad error
	if prof == nil {
		prof, eLoad = profile.Load(filepath.Join(dir, "cra.yml"))
	}
	e = eLoad
	if e != nil && !os.IsNotExist(e) {
		return Report{}, rungrad.NewError(1, "Cannot load cra.yml: "+safeError(e)+"; correct cra.yml and run fendkit scan again")
	}
	if prof != nil && prof.Product.Version != nil {
		p.Version = prof.Product.Version
		if p.DetectedVersion != nil && *p.Version != *p.DetectedVersion {
			p.Notes = append(p.Notes, "product.version overrides the detected version; review both versions in inventory.json")
		}
	}
	var release *string
	if cmd.Flags().Changed("release") {
		value, _ := cmd.Flags().GetString("release")
		release = &value
	}
	inv, e := inventory.BuildWithOptions(dir, p, inventory.Options{Release: release, Profile: prof})
	if e != nil {
		return Report{}, rungrad.NewError(2, e.Error())
	}
	digest, e := inv.Digest()
	if e != nil {
		return Report{}, e
	}
	id := make([]byte, 16)
	if _, e = rand.Read(id); e != nil {
		return Report{}, rungrad.NewError(2, "Cannot create scan identity; run fendkit scan again")
	}
	offline, _ := cmd.Flags().GetBool("offline")
	// A preview avoids disclosing package information through lookups.
	findings, reasons := client.Lookup(cmd.Context(), inv, offline || f.DryRun())
	if f.DryRun() && !offline {
		reasons = []string{"Dry run: vulnerability lookups have not run"}
	}
	r := Report{ScanID: hex.EncodeToString(id), ScannedAt: time.Now().UTC(), ProductVersion: inv.Product.Version, InventoryDigest: digest, Complete: len(reasons) == 0, Offline: offline, DryRun: f.DryRun(), Output: "cra/reports/inventory.json", IncompleteReasons: reasons, Inventory: inv}
	vr := vulns.Report{ScanID: r.ScanID, ScannedAt: r.ScannedAt, ProductVersion: r.ProductVersion, ProductPURL: inv.Product.PURL, InventoryDigest: digest, Complete: r.Complete, Reason: reasons, Findings: findings, CoverageGaps: inv.CoverageGaps}
	vulns.Apply(&vr, prof)
	r.FindingCount = len(vr.Findings)
	if _, e = vulns.VEX(vr, prof); e != nil {
		return Report{}, rungrad.NewError(1, e.Error())
	}

	if !f.DryRun() {
		if e := vulns.Write(dir, vr, prof); e != nil {
			return Report{}, rungrad.NewError(2, e.Error())
		}
		if e := writeReport(dir, r, prof); e != nil {
			return Report{}, rungrad.NewError(2, e.Error())
		}
	}
	return r, nil
}
