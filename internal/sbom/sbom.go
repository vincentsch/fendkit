package sbom

import (
	"io"
	"strconv"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/vincentsch/conformline/internal/inventory"
	"github.com/vincentsch/conformline/internal/profile"
)

type Provenance struct {
	ScanID            string
	ScannedAt         time.Time
	InventoryDigest   string
	Complete          bool
	Offline           bool
	IncompleteReasons []string
}

func New(inv inventory.Inventory, prof *profile.Profile, provenance Provenance, toolVersion string) *cdx.BOM {
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6
	product := cdx.Component{Type: cdx.ComponentTypeApplication, Name: "product", PackageURL: inv.Product.PURL, BOMRef: inv.Product.PURL}
	if inv.Product.Name != nil {
		product.Name = *inv.Product.Name
	}
	if inv.Product.Version != nil {
		product.Version = *inv.Product.Version
	}
	if prof != nil && prof.Manufacturer.Name != nil {
		product.Supplier = &cdx.OrganizationalEntity{Name: *prof.Manufacturer.Name}
	}
	properties := []cdx.Property{
		{Name: "conformline:scan_id", Value: provenance.ScanID},
		{Name: "conformline:scanned_at", Value: provenance.ScannedAt.Format(time.RFC3339Nano)},
		{Name: "conformline:inventory_digest", Value: provenance.InventoryDigest},
		{Name: "conformline:complete", Value: strconv.FormatBool(provenance.Complete)},
		{Name: "conformline:offline", Value: strconv.FormatBool(provenance.Offline)},
	}
	for _, reason := range provenance.IncompleteReasons {
		properties = append(properties, cdx.Property{Name: "conformline:incomplete_reason", Value: reason})
	}
	if inv.Release != nil {
		properties = append(properties, cdx.Property{Name: "conformline:release", Value: *inv.Release})
	}
	tools := []cdx.Component{{Type: cdx.ComponentTypeApplication, Name: "conformline", Version: toolVersion}}
	bom.Metadata = &cdx.Metadata{Timestamp: provenance.ScannedAt.Format(time.RFC3339), Component: &product, Tools: &cdx.ToolsChoice{Components: &tools}, Properties: &properties}
	components := []cdx.Component{}
	for _, c := range inv.Components {
		scope := cdx.ScopeRequired
		shipped := "unknown"
		if c.Shipped != nil {
			shipped = strconv.FormatBool(*c.Shipped)
			if !*c.Shipped {
				scope = cdx.ScopeExcluded
			}
		}
		props := []cdx.Property{{Name: "conformline:shipped", Value: shipped}}
		occurrences := []cdx.EvidenceOccurrence{}
		seen := map[string]bool{}
		for _, ev := range c.Evidence {
			props = append(props, cdx.Property{Name: "conformline:source", Value: ev.File + " (" + ev.Method + ")"})
			if ev.Banner != "" {
				props = append(props, cdx.Property{Name: "conformline:banner", Value: ev.Banner})
			}
			loc := ev.Path
			if loc == "" {
				loc = ev.File
			}
			if !seen[loc] {
				occurrences = append(occurrences, cdx.EvidenceOccurrence{Location: loc})
				seen[loc] = true
			}
		}
		if c.Note != "" {
			props = append(props, cdx.Property{Name: "conformline:note", Value: c.Note})
		}
		item := cdx.Component{Type: cdx.ComponentTypeLibrary, Name: c.Name, PackageURL: c.PURL, BOMRef: c.PURL, Scope: scope, Properties: &props, Evidence: &cdx.Evidence{Occurrences: &occurrences}}
		if c.Version != nil {
			item.Version = *c.Version
		}
		if c.Modified {
			item.Modified = &c.Modified
		}
		components = append(components, item)
	}
	bom.Components = &components
	return bom
}

func Write(w io.Writer, bom *cdx.BOM) error {
	encoder := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	encoder.SetPretty(true)
	return encoder.EncodeVersion(bom, cdx.SpecVersion1_6)
}
