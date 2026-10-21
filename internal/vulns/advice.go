package vulns

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/vincentsch/fendkit/internal/inventory"
)

var stableVersion = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?(?:\.(0|[1-9][0-9]*))?$`)

// Only ordinary numeric releases are comparable here. Other version schemes use source advice.
func numeric(v string) ([]uint64, bool) {
	if !stableVersion.MatchString(v) {
		return nil, false
	}
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	out := make([]uint64, 4)
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}
func compare(a, b string) (int, bool) {
	av, ok := numeric(a)
	if !ok {
		return 0, false
	}
	bv, ok := numeric(b)
	if !ok {
		return 0, false
	}
	return slices.Compare(av, bv), true
}
func resolved(f Finding) bool { return f.Status == "fixed" || f.Status == "not_affected" }
func outside(a Advisory, c inventory.Component, candidate string) bool {
	matched := false
	for _, aff := range a.Affected {
		if !matches(aff, c) {
			continue
		}
		matched = true
		if len(aff.Ranges) == 0 && len(aff.Versions) == 0 {
			return false
		}
		for _, v := range aff.Versions {
			cmp, ok := compare(candidate, v)
			if (ok && cmp == 0) || strings.TrimPrefix(strings.Split(v, "+")[0], "v") == strings.TrimPrefix(candidate, "v") {
				return false
			}
		}
		for _, r := range aff.Ranges {
			if (r.Type != "SEMVER" && r.Type != "ECOSYSTEM") || len(r.Events) == 0 {
				return false
			}
			// Sort boundaries because OSV does not require sorted events.
			events := slices.Clone(r.Events)
			value := func(e Event) string {
				if e.Introduced != "" {
					return e.Introduced
				}
				if e.Fixed != "" {
					return e.Fixed
				}
				if e.LastAffected != "" {
					return e.LastAffected
				}
				return e.Limit
			}
			for _, e := range events {
				if e.Limit != "" {
					return false
				}
				if value(e) != "0" {
					if _, ok := numeric(value(e)); !ok {
						return false
					}
				}
			}
			slices.SortFunc(events, func(a, b Event) int {
				av, bv := value(a), value(b)
				if av == bv {
					return 0
				}
				if av == "0" {
					return -1
				}
				if bv == "0" {
					return 1
				}
				n, _ := compare(av, bv)
				return n
			})
			affected := false
			hasIntroduction := false
			for _, e := range events {
				boundary := value(e)
				cmp := 1
				if boundary != "0" {
					cmp, _ = compare(candidate, boundary)
				}
				if e.Introduced != "" {
					hasIntroduction = true
					if cmp >= 0 {
						affected = true
					}
				}
				if e.Fixed != "" && cmp >= 0 {
					affected = false
				}
				if e.LastAffected != "" && cmp > 0 {
					affected = false
				}
			}
			if !hasIntroduction || affected {
				return false
			}
		}
	}
	return matched
}
func SafeFix(c inventory.Component, findings []Finding) string {
	if c.Modified || c.LookupVersion == nil {
		return ""
	}
	installed, ok := numeric(*c.LookupVersion)
	if !ok {
		return ""
	}
	candidates := []string{}
	open := []Advisory{}
	for _, f := range findings {
		if f.Component.PURL == c.PURL && !resolved(f) {
			for _, a := range f.Advisories {
				open = append(open, a)
				candidates = append(candidates, Fixed(a, c)...)
			}
		}
	}
	candidates = unique(candidates)
	slices.SortFunc(candidates, func(a, b string) int {
		n, ok := compare(a, b)
		if ok {
			return n
		}
		return strings.Compare(a, b)
	})
	for _, v := range candidates {
		parsed, ok := numeric(v)
		cmp, comparable := compare(v, *c.LookupVersion)
		if !ok || !comparable || parsed[0] != installed[0] || cmp < 0 {
			continue
		}
		safe := len(open) > 0
		for _, a := range open {
			if !outside(a, c, v) {
				safe = false
				break
			}
		}
		if safe {
			return v
		}
	}
	return ""
}
func Advice(c inventory.Component, findings []Finding) string {
	open := false
	for _, f := range findings {
		if f.Component.PURL == c.PURL && !resolved(f) {
			open = true
		}
	}
	if !open {
		return "All saved findings for this component have a fixed or not_affected decision. Review the recorded reasons below."
	}
	if v := SafeFix(c, findings); v != "" {
		return fmt.Sprintf("Update %s from %s to %s.", inventory.LibraryDisplayName(c.Name), *c.Version, v)
	}
	return "Review the fixes and source links below for each advisory. The saved evidence does not establish one update version."
}
