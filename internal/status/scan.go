package status

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/vincentsch/fendkit/internal/inventory"
	"github.com/vincentsch/fendkit/internal/profile"
	"github.com/vincentsch/fendkit/internal/vulns"
)

var retrySuffix = regexp.MustCompile(`; run fendkit scan again[.!?]?$`)

func scanReason(reason string) string {
	return strings.TrimSpace(retrySuffix.ReplaceAllString(strings.TrimSpace(reason), ""))
}

// evaluateScan keeps headline precedence separate from local recovery prerequisites.
func evaluateScan(root string, p *profile.Profile, now time.Time, r *Result) (bool, string) {
	var saved Scan
	inventoryBytes, inventoryErr := os.ReadFile(filepath.Join(root, "cra/reports/inventory.json"))
	invOK := inventoryErr == nil && json.Unmarshal(inventoryBytes, &saved) == nil
	usable := invOK && saved.ScanID != "" && saved.InventoryDigest != "" && !saved.ScannedAt.IsZero()
	var vr vulns.Report
	vulnOK := readJSON(root, "vulnerabilities.json", &vr)
	issue := func(s string) { r.ScanIssues = append(r.ScanIssues, sentence(scanReason(s))) }
	reportsMismatch, changed, old := false, false, false
	releaseRepair, sourceRepair := "", ""
	if !usable {
		switch {
		case os.IsNotExist(inventoryErr):
			issue("Inventory scan evidence is missing: cra/reports/inventory.json.")
		case !invOK:
			issue("Inventory scan evidence is unreadable: cra/reports/inventory.json; check its JSON and permissions.")
		default:
			fields := []string{}
			if saved.ScanID == "" {
				fields = append(fields, "scan_id")
			}
			if saved.InventoryDigest == "" {
				fields = append(fields, "inventory_digest")
			}
			if saved.ScannedAt.IsZero() {
				fields = append(fields, "scanned_at")
			}
			issue("Inventory scan evidence is missing metadata: " + strings.Join(fields, ", ") + ".")
		}
	} else {
		r.ScannedAt = saved.ScannedAt
		r.Components = saved.Components
		r.CoverageGaps = saved.CoverageGaps
		digest, _ := saved.Inventory.Digest()
		if digest != saved.InventoryDigest {
			reportsMismatch = true
			issue("Saved inventory content differs from its scan digest.")
		}
		current, err := inventory.BuildWithOptions(root, r.Product, inventory.Options{Release: saved.Release, ReplayRelease: true, Profile: p})
		if err != nil {
			var releaseErr *inventory.ReleaseError
			if errors.As(err, &releaseErr) {
				releaseRepair = err.Error()
				issue("The recorded release " + Value(saved.Release) + " is unavailable: " + err.Error())
			} else {
				sourceRepair = err.Error()
				issue("Local inventory cannot be rebuilt: " + err.Error())
			}
		} else {
			d, _ := current.Digest()
			r.Product = current.Product
			if d != saved.InventoryDigest {
				changed = true
				issue("Inventory content changed since the saved scan.")
			}
		}
		// A source failure can hide a second, independently repairable release failure.
		if sourceRepair != "" && saved.Release != nil {
			if err := inventory.ValidateRelease(root, r.Product, *saved.Release); err != nil {
				releaseRepair = err.Error()
				issue("The recorded release " + *saved.Release + " is unavailable: " + err.Error())
			}
		}
		if !same(saved.ProductVersion, r.Product.Version) {
			changed = true
			issue("Product version changed since the saved scan.")
		}
		old = now.Sub(saved.ScannedAt) > 7*24*time.Hour
		if old {
			issue("The scan is older than seven days.")
		}
	}
	if !vulnOK || vr.ScanID == "" {
		reportsMismatch = true
		issue("Vulnerability scan evidence is missing or unreadable.")
	} else {
		// Keep known policy failures visible even when saved reports disagree.
		vulns.Apply(&vr, p)
		r.Findings = vr.Findings
		for _, f := range r.Findings {
			if !slices.ContainsFunc(r.Components, func(c inventory.Component) bool { return c.PURL == f.Component.PURL }) {
				r.Components = append(r.Components, f.Component)
			}
		}
		r.CoverageGaps = append(r.CoverageGaps, vr.CoverageGaps...)
		if !invOK || vr.ScanID != saved.ScanID || vr.InventoryDigest != saved.InventoryDigest || !vr.ScannedAt.Equal(saved.ScannedAt) || !same(vr.ProductVersion, saved.ProductVersion) || vr.Complete != saved.Complete {
			reportsMismatch = true
			issue("Inventory and vulnerability evidence do not belong to the same scan.")
		}
	}
	incomplete := invOK && !saved.Complete || vulnOK && !vr.Complete
	firstReason := "the saved scan did not finish"
	if incomplete {
		reasons := []string{}
		for _, raw := range append(append([]string{}, saved.IncompleteReasons...), vr.Reason...) {
			reason := scanReason(raw)
			if reason != "" && !slices.Contains(reasons, sentence(reason)) {
				if len(reasons) == 0 {
					firstReason = strings.TrimRight(reason, ".!?")
				}
				reasons = append(reasons, sentence(reason))
			}
		}
		issue("The last scan is incomplete. " + strings.Join(reasons, " "))
	}
	var bom struct {
		Metadata struct {
			Component  struct{ Version string }
			Properties []struct{ Name, Value string }
		}
	}
	bomOK := readJSON(root, "sbom.cdx.json", &bom)
	props := map[string]string{}
	for _, v := range bom.Metadata.Properties {
		props[v.Name] = v.Value
	}
	if !bomOK {
		reportsMismatch = true
		issue("SBOM scan evidence is missing or unreadable.")
	} else if props["fendkit:scan_id"] != saved.ScanID || props["fendkit:inventory_digest"] != saved.InventoryDigest || props["fendkit:scanned_at"] != saved.ScannedAt.Format(time.RFC3339Nano) || props["fendkit:complete"] != fmt.Sprint(saved.Complete) || (saved.ProductVersion == nil && bom.Metadata.Component.Version != "" || saved.ProductVersion != nil && bom.Metadata.Component.Version != *saved.ProductVersion) {
		reportsMismatch = true
		issue("SBOM evidence does not belong to the saved scan.")
	}
	r.ScanState, r.ScanDetail = "complete", "complete"
	reason := ""
	advice := "."
	switch {
	case !usable:
		r.ScanState, r.ScanDetail = "missing", "missing"
		reason = "No usable saved scan is available."
	case incomplete && saved.Offline:
		r.ScanState, r.ScanDetail = "incomplete", "incomplete (lookups did not run)"
		reason = "Vulnerability lookups did not run."
		advice = " with network access."
	case incomplete:
		r.ScanState, r.ScanDetail = "incomplete", "incomplete (lookups failed)"
		reason = "Vulnerability lookups failed: " + firstReason + "."
		advice = " again, or fendkit doctor to check the connection."
	case reportsMismatch:
		r.ScanState, r.ScanDetail = "incomplete", "incomplete (reports do not match)"
		reason = "Saved reports are missing or do not belong to one scan."
	case changed:
		r.ScanState, r.ScanDetail = "stale", "stale (components changed)"
		reason = "Your components or product version changed since the last scan."
	case old:
		r.ScanState, r.ScanDetail = "stale", "stale (older than seven days)"
		reason = "The last scan is older than seven days."
	case releaseRepair != "":
		r.ScanState, r.ScanDetail = "stale", "stale (release unavailable)"
	case sourceRepair != "":
		r.ScanState, r.ScanDetail = "stale", "stale (inventory unavailable)"
	}
	r.ScanComplete = r.ScanState == "complete"
	if !r.ScanComplete {
		parts := []string{}
		if reason != "" {
			parts = append(parts, reason)
		}
		if sourceRepair != "" {
			parts = append(parts, "Repair "+sentence(sourceRepair))
		}
		if releaseRepair != "" {
			parts = append(parts, "Restore the recorded release "+Value(saved.Release)+".")
		}
		command := "fendkit scan"
		if saved.Release != nil {
			command += " --release " + shellQuote(*saved.Release)
		}
		instruction := "Run " + command + advice
		if sourceRepair != "" || releaseRepair != "" {
			instruction = "Then run " + command + advice
		}
		parts = append(parts, instruction)
		if releaseRepair != "" {
			parts = append(parts, "To scan a replacement release, pass its path with --release.")
		}
		r.ScanRecovery = strings.Join(parts, " ")
	}
	return bomOK, bom.Metadata.Component.Version
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
