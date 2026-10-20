package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vincentsch/conformline/internal/detect"
	"github.com/vincentsch/conformline/internal/inventory"
	"github.com/vincentsch/conformline/internal/profile"
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
	inventory.Inventory
}

func New() *rungrad.App {
	app := rungrad.New(rungrad.AppConfig{Name: "conformline", Short: "Prepare your Cyber Resilience Act evidence", Long: "Find your product and its dependencies, and record what still needs review.", Version: "0.1.0", ErrorPolicy: &rungrad.ErrorPolicy{
		Render: func(ctx rungrad.ErrorContext) error {
			var pending *incomplete
			if errors.As(ctx.Err, &pending) {
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
	dir := "."
	app.Root().PersistentFlags().StringVar(&dir, "dir", ".", "Project root")
	app.AddCommand(&rungrad.Command{Use: "scan", Short: "Find the product and inventory its dependencies offline", Long: "Read WordPress headers, Composer and npm metadata. Write cra/reports/inventory.json.\nScans currently run offline and exit 11 because vulnerability lookups have not run.\nAn existing cra.yml is validated; only product.version is applied.\nUse --dry-run to preview the result without writing files.", Examples: []string{"conformline scan --offline", "conformline scan --offline --dir ./my-plugin --json", "conformline scan --offline --dry-run"}, OutputModes: []string{rungrad.OutputModeHuman, rungrad.OutputModeJSON}, Mutates: true, Args: cobra.NoArgs, Configure: func(cmd *cobra.Command) {
		cmd.Flags().Bool("offline", false, "Skip vulnerability lookups (currently always offline)")
	}, Run: func(f *rungrad.Factory, cmd *cobra.Command, args []string) error {
		p, e := detect.Detect(dir)
		if e != nil {
			return rungrad.NewError(2, e.Error())
		}
		prof, e := profile.Load(filepath.Join(dir, "cra.yml"))
		if e != nil && !os.IsNotExist(e) {
			return rungrad.NewError(1, "Cannot load cra.yml: "+safeError(e)+"; correct cra.yml and run conformline scan again")
		}
		if prof != nil && prof.Product.Version != nil {
			p.Version = prof.Product.Version
			if p.DetectedVersion != nil && *p.Version != *p.DetectedVersion {
				p.Notes = append(p.Notes, "product.version overrides the detected version; review both versions in inventory.json")
			}
		}
		inv, e := inventory.Build(dir, p)
		if e != nil {
			return rungrad.NewError(2, e.Error())
		}
		digest, e := inv.Digest()
		if e != nil {
			return e
		}
		id := make([]byte, 16)
		if _, e = rand.Read(id); e != nil {
			return rungrad.NewError(2, "Cannot create scan identity; run conformline scan again")
		}
		r := Report{ScanID: hex.EncodeToString(id), ScannedAt: time.Now().UTC(), ProductVersion: p.Version, InventoryDigest: digest, Offline: true, DryRun: f.DryRun(), Output: "cra/reports/inventory.json", IncompleteReasons: []string{"Offline scan: vulnerability lookups have not run"}, Inventory: inv}
		for _, gap := range inv.CoverageGaps {
			r.IncompleteReasons = append(r.IncompleteReasons, gap.Message)
		}
		if !f.DryRun() {
			if e := writeReport(dir, r); e != nil {
				return rungrad.NewError(2, e.Error())
			}
		}
		if e := f.WriteResult(r, func(w io.Writer) { render(w, r) }); e != nil {
			return e
		}
		return &incomplete{}
	}})
	return app
}

// A scan result has already been printed; incompleteness is an exit status.
type incomplete struct{}

func (*incomplete) Error() string { return "Offline scan incomplete" }
func (*incomplete) ExitCode() int { return 11 }
func safeError(e error) string {
	if _, ok := e.(*os.PathError); ok {
		return "file cannot be read; check its permissions"
	}
	return e.Error()
}
func writeReport(root string, r Report) error {
	dir := filepath.Join(root, "cra", "reports")
	if e := os.MkdirAll(dir, 0755); e != nil {
		return fmt.Errorf("cannot create cra/reports; check project permissions")
	}
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
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
	return nil
}
func render(w io.Writer, r Report) {
	labels := map[string]string{"wordpress-plugin": "WordPress plugin", "wordpress-theme": "WordPress theme", "composer-package": "Composer package", "npm-package": "npm package", "other": "Product"}
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
		runtime, dev, unknown := 0, 0, 0
		for _, c := range r.Components {
			if c.Ecosystem != eco {
				continue
			}
			if c.Development {
				dev++
			} else if c.Shipped == nil {
				unknown++
			} else if *c.Shipped {
				runtime++
			}
		}
		label := "Composer"
		if eco == "npm" {
			label = "npm"
		}
		if eco == "npm" && runtime == 0 && unknown == 0 && dev > 0 {
			fmt.Fprintf(w, "  %-18s %d build tools (not shipped)\n", label, dev)
			continue
		}
		fmt.Fprintf(w, "  %-18s %d packages to ship, %d for development only (not shipped)", label, runtime, dev)
		if unknown > 0 {
			fmt.Fprintf(w, ", %d shipped: unknown (may be compiled into your bundles); set product.release", unknown)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "  Bundled JS         not checked yet\n  Release file       not checked yet")
	for _, note := range r.Product.Notes {
		fmt.Fprintln(w, "  Note               "+note)
	}
	for _, gap := range r.CoverageGaps {
		fmt.Fprintln(w, "  Coverage gap       "+gap.Message)
	}
	if r.Product.Version == nil {
		fmt.Fprintln(w, "  Next               Set product.version in cra.yml; the product version is unknown")
	}
	if r.DryRun {
		fmt.Fprintln(w, "\nDRY RUN: would write "+r.Output+"; no changes were made")
	} else {
		fmt.Fprintln(w, "\nInventory: "+r.Output)
	}
	fmt.Fprintln(w, "Offline scan incomplete: vulnerability lookups have not run.")
}
