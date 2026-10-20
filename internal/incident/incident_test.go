package incident

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func instant(t *testing.T, s string) time.Time {
	t.Helper()
	v, e := time.Parse(time.RFC3339, s)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func record(t *testing.T, kind, aware, zone string) Record {
	return Record{Version: 1, ID: "inc-1", Type: kind, Title: "Active exploitation", AwareAt: instant(t, aware), TimeZone: zone, Submissions: map[string]Submission{}}
}
func TestElapsedDeadlinesAcrossDaylightSaving(t *testing.T) {
	r := record(t, Exploited, "2026-10-24T10:00:00+02:00", "Europe/Berlin")
	v := Describe(r, r.AwareAt.Add(2*time.Hour+20*time.Minute))
	if got := v.Stages[0]; got.DueAt.Sub(r.AwareAt) != 24*time.Hour || !strings.Contains(got.Description, "2026-10-25 09:00:00 CET +01:00") || !strings.Contains(got.Description, "due in 21 h 40 min") {
		t.Fatal(got)
	}
	if v.Stages[1].DueAt.Sub(r.AwareAt) != 72*time.Hour {
		t.Fatal(v)
	}
	if v.Stages[2].DueAt != nil || !strings.Contains(v.Stages[2].Description, "Pending") {
		t.Fatal(v)
	}
	fix := instant(t, "2027-03-27T10:00:00+01:00")
	r.FixAvailableAt = &fix
	v = Describe(r, fix)
	if v.Stages[2].DueAt.Sub(fix) != 14*24*time.Hour || !strings.Contains(v.Stages[2].Description, "2027-04-10 11:00:00 CEST +02:00") {
		t.Fatal(v)
	}
	v = Describe(r, r.AwareAt.Add(27*time.Hour))
	if !v.Stages[0].Overdue || !strings.Contains(v.Stages[0].Description, "overdue by 3 h") {
		t.Fatal(v)
	}
	r.Submissions["early-warning"] = Submission{SubmittedAt: r.AwareAt.Add(26 * time.Hour)}
	v = Describe(r, r.AwareAt.Add(28*time.Hour))
	if v.Stages[0].Overdue || !strings.Contains(v.Stages[0].Description, "filed late by 2 h") {
		t.Fatal(v)
	}
}
func TestCalendarMonthFinalDeadline(t *testing.T) {
	for _, tc := range []struct{ at, want string }{
		{"2027-01-31T10:00:00+01:00", "2027-02-28T10:00:00+01:00"},
		{"2028-01-31T10:00:00+01:00", "2028-02-29T10:00:00+01:00"},
		{"2026-10-24T10:00:00+02:00", "2026-11-24T10:00:00+01:00"},
		{"2026-12-31T10:00:00+01:00", "2027-01-31T10:00:00+01:00"},
	} {
		t.Run(tc.at, func(t *testing.T) {
			at := instant(t, tc.at)
			r := record(t, Severe, at.Add(-24*time.Hour).Format(time.RFC3339), "Europe/Berlin")
			provisional := Describe(r, at).Stages[2]
			if !strings.Contains(provisional.Description, "Provisional") {
				t.Fatal(provisional)
			}
			r.Submissions["notification"] = Submission{SubmittedAt: at}
			actual := Describe(r, at).Stages[2]
			if !actual.DueAt.Equal(instant(t, tc.want)) || actual.DueAt.Equal(*provisional.DueAt) || strings.Contains(actual.Description, "Provisional") {
				t.Fatal(actual, provisional)
			}
		})
	}
}
func TestZoneResolutionAndInput(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv("TZ", "Europe/Berlin")
	if z := ResolveZone(os.Getenv("TZ"), missing); z.String() != "Europe/Berlin" {
		t.Fatal(z)
	}
	if z := ResolveZone("invalid/zone", missing); z != time.UTC {
		t.Fatal(z)
	}
	if z := ResolveZone("Local", missing); z != time.UTC {
		t.Fatal(z)
	}
	dir := t.TempDir()
	link := filepath.Join(dir, "localtime")
	target := filepath.Join(dir, "zoneinfo", "Europe", "Berlin")
	if e := os.MkdirAll(filepath.Dir(target), 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(target, []byte(""), 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(target, link); e != nil {
		t.Skip("symlinks unavailable", e)
	}
	if z := ResolveZone("invalid", link); z.String() != "Europe/Berlin" {
		t.Fatal(z)
	}
	z, _ := time.LoadLocation("Europe/Berlin")
	local, e := ParseTime("2026-10-24 10:00", z)
	if e != nil || !local.Equal(instant(t, "2026-10-24T08:00:00Z")) {
		t.Fatal(local, e)
	}
	explicit, e := ParseTime("2026-10-24T10:00:00-04:00", z)
	if e != nil || !strings.Contains(FormatTime(explicit, z.String()), "16:00:00 CEST") {
		t.Fatal(explicit, e)
	}
	for _, s := range []string{"2026-02-30 10:00", "tomorrow", "2027-03-28 02:30"} {
		if _, e := ParseTime(s, z); e == nil {
			t.Fatal("accepted invalid local time", s)
		}
	}
}
func TestRecordRoundTripAndValidation(t *testing.T) {
	root := t.TempDir()
	r := record(t, Exploited, "2026-10-20T10:00:00Z", "UTC")
	if e := Create(root, r, map[string]string{}); e != nil {
		t.Fatal(e)
	}
	r.Notes = "Maker notes"
	if e := Save(root, r); e != nil {
		t.Fatal(e)
	}
	saved, e := Load(root, r.ID)
	if e != nil || saved.Notes != r.Notes {
		t.Fatal(saved, e)
	}
	id, e := NextID(root)
	if e != nil || id != "inc-2" {
		t.Fatal(id, e)
	}
	if _, e := Load(root, "../inc-1"); !os.IsNotExist(e) {
		t.Fatal(e)
	}
	if e := Create(root, r, nil); e == nil {
		t.Fatal("overwrote incident")
	}
	r.TimeZone = "Local"
	if e := Save(root, r); e == nil {
		t.Fatal("accepted non-IANA zone")
	}
}
