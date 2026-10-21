package status

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vincentsch/fendkit/internal/profile"
	"github.com/vincentsch/fendkit/internal/vulns"
)

// Captured from the pre-change scanner with complete loopback provider responses.
// Keep the original serialized product shape and digest; newer fields were absent.
const legacyInventoryReport = `{
  "scan_id": "56d6551cfc44795eae1c3fb29c20cc0f",
  "scanned_at": "2026-10-21T14:57:44.551931872Z",
  "product_version": "1.0.0",
  "inventory_digest": "246b6a3f0d6c7966ff7bf4f17b13e03152749892a0db7c38ad9cdcc4b0f9ff02",
  "complete": true,
  "incomplete_reasons": [],
  "offline": false,
  "dry_run": false,
  "output": "cra/reports/inventory.json",
  "finding_count": 0,
  "product": {
    "purl": "pkg:npm/sample@1.0.0",
    "type": "npm-package",
    "name": "sample",
    "version": "1.0.0",
    "detected_version": "1.0.0",
    "description": null,
    "evidence": [
      "package.json"
    ],
    "notes": []
  },
  "release": null,
  "components": [],
  "coverage_gaps": []
}
`

func TestLegacyScanProvenance(t *testing.T) {
	for _, tampered := range []bool{false, true} {
		name := "untouched"
		if tampered {
			name = "modified saved inventory"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			put(t, root, "package.json", `{"name":"sample","version":"1.0.0"}`)
			p, err := profile.Parse([]byte("version: 1\nrole: {answer: not-in-scope}\n"))
			if err != nil {
				t.Fatal(err)
			}
			var saved Scan
			if err = json.Unmarshal([]byte(legacyInventoryReport), &saved); err != nil {
				t.Fatal(err)
			}
			if !tampered {
				digest, err := saved.Inventory.Digest()
				if err != nil {
					t.Fatal(err)
				}
				if digest != saved.InventoryDigest {
					t.Errorf("untouched legacy content has different digest: %s want %s", digest, saved.InventoryDigest)
				}
			}
			vr := vulns.Report{ScanID: saved.ScanID, ScannedAt: saved.ScannedAt, ProductVersion: saved.ProductVersion, ProductPURL: saved.Product.PURL, InventoryDigest: saved.InventoryDigest, Complete: true}
			saveEvidence(t, root, saved, vr)
			raw := legacyInventoryReport
			if tampered {
				raw = strings.Replace(raw, `"name": "sample"`, `"name": "modified"`, 1)
			}
			put(t, root, "cra/reports/inventory.json", raw)
			result, err := Evaluate(root, p, saved.ScannedAt, false)
			if err != nil {
				t.Fatal(err)
			}
			if result.ExitCode != 11 || result.ScanComplete {
				t.Fatal(result)
			}
			issues := strings.Join(result.ScanIssues, " ")
			if !strings.Contains(issues, "provenance is unavailable") {
				t.Fatal(issues)
			}
			if tampered {
				if result.ScanDetail != "incomplete (reports do not match)" || !strings.Contains(issues, "Saved inventory content differs") {
					t.Fatal(result.ScanDetail, issues)
				}
			} else {
				if result.ScanDetail != "stale (release provenance unavailable)" {
					t.Fatal(result.ScanDetail, issues)
				}
				if strings.Contains(issues, "differs from its scan digest") || strings.Contains(issues, "Inventory content changed") {
					t.Fatal("false legacy mismatch", issues)
				}
			}
		})
	}
}
