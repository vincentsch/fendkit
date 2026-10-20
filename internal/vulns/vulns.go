package vulns

import (
	"slices"
	"strings"
	"time"

	"github.com/vincentsch/conformline/internal/inventory"
	"github.com/vincentsch/conformline/internal/profile"
)

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}
type Affected struct {
	Package          Package    `json:"package"`
	Ranges           []Range    `json:"ranges"`
	Versions         []string   `json:"versions,omitempty"`
	Severity         []Severity `json:"severity,omitempty"`
	DatabaseSpecific struct {
		Severity string `json:"severity,omitempty"`
	} `json:"database_specific"`
}
type Advisory struct {
	ID               string     `json:"id"`
	Aliases          []string   `json:"aliases"`
	Summary          string     `json:"summary"`
	Published        string     `json:"published"`
	Withdrawn        string     `json:"withdrawn,omitempty"`
	Affected         []Affected `json:"affected"`
	Severity         []Severity `json:"severity,omitempty"`
	DatabaseSpecific struct {
		Severity string `json:"severity,omitempty"`
	} `json:"database_specific"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}
type Finding struct {
	IDs            []string            `json:"ids"`
	Component      inventory.Component `json:"component"`
	Advisories     []Advisory          `json:"advisories"`
	KnownExploited bool                `json:"known_exploited"`
	Status         string              `json:"status"`
	Decision       *profile.Triage     `json:"decision,omitempty"`
}
type Report struct {
	ScanID          string          `json:"scan_id"`
	Complete        bool            `json:"complete"`
	Reason          []string        `json:"reason"`
	ScannedAt       time.Time       `json:"scanned_at"`
	ProductVersion  *string         `json:"product_version"`
	ProductPURL     string          `json:"product_purl"`
	InventoryDigest string          `json:"inventory_digest"`
	Findings        []Finding       `json:"findings"`
	CoverageGaps    []inventory.Gap `json:"coverage_gaps"`
}

func ecosystem(c inventory.Component) string {
	switch c.Ecosystem {
	case "npm":
		return "npm"
	case "composer":
		return "Packagist"
	}
	return ""
}
func matches(a Affected, c inventory.Component) bool {
	return a.Package.Name == c.Name && a.Package.Ecosystem == ecosystem(c)
}
func IDs(a Advisory) []string { return unique(append([]string{a.ID}, a.Aliases...)) }
func unique(ss []string) []string {
	out := []string{}
	for _, s := range ss {
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}
func overlaps(a, b []string) bool {
	for _, s := range a {
		if slices.Contains(b, s) {
			return true
		}
	}
	return false
}
func Group(c inventory.Component, advisories []Advisory, kev map[string]bool) []Finding {
	groups := []Finding{}
	for _, a := range advisories {
		if a.Withdrawn != "" {
			continue
		}
		f := Finding{IDs: IDs(a), Component: c, Advisories: []Advisory{a}, Status: "untriaged"}
		// An alias can join two groups already encountered in this response.
		for i := 0; i < len(groups); {
			if overlaps(f.IDs, groups[i].IDs) {
				f.IDs = unique(append(f.IDs, groups[i].IDs...))
				f.Advisories = append(f.Advisories, groups[i].Advisories...)
				groups = append(groups[:i], groups[i+1:]...)
				i = 0
			} else {
				i++
			}
		}
		groups = append(groups, f)
	}
	for i := range groups {
		slices.SortFunc(groups[i].Advisories, func(a, b Advisory) int { return strings.Compare(a.ID, b.ID) })
		for _, id := range groups[i].IDs {
			if kev[id] {
				groups[i].KnownExploited = true
			}
		}
	}
	slices.SortFunc(groups, func(a, b Finding) int { return strings.Compare(a.IDs[0], b.IDs[0]) })
	return groups
}
func Apply(r *Report, p *profile.Profile) {
	for i := range r.Findings {
		f := &r.Findings[i]
		f.Status = "untriaged"
		f.Decision = nil
		if p == nil {
			continue
		}
		for _, t := range p.Triage {
			if t.Advisory != nil && t.Component != nil && *t.Component == f.Component.PURL && slices.Contains(f.IDs, *t.Advisory) {
				copy := t
				f.Decision = &copy
				f.Status = *t.Status
			}
		}
	}
}
func Fixed(a Advisory, c inventory.Component) []string {
	out := []string{}
	for _, aff := range a.Affected {
		if matches(aff, c) {
			for _, r := range aff.Ranges {
				if r.Type == "SEMVER" || r.Type == "ECOSYSTEM" {
					for _, e := range r.Events {
						if e.Fixed != "" {
							out = append(out, e.Fixed)
						}
					}
				}
			}
		}
	}
	return unique(out)
}
func Rating(a Advisory, c inventory.Component) string {
	label := a.DatabaseSpecific.Severity
	vectors := []string{}
	for _, s := range a.Severity {
		vectors = append(vectors, s.Score)
	}
	for _, aff := range a.Affected {
		if matches(aff, c) {
			if label == "" {
				label = aff.DatabaseSpecific.Severity
			}
			for _, s := range aff.Severity {
				vectors = append(vectors, s.Score)
			}
		}
	}
	if label != "" {
		return label
	}
	if len(vectors) > 0 {
		return "not rated (" + strings.Join(unique(vectors), ", ") + ")"
	}
	return "not rated"
}
