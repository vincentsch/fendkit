package incident

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"

	"gopkg.in/yaml.v3"
)

const Exploited = "exploited-vulnerability"
const Severe = "severe-incident"
const Legal = "Conformline helps prepare evidence and does not give legal advice. A person reviews the drafts and submits reports to ENISA."

var Stages = []string{"early-warning", "notification", "final"}
var validID = regexp.MustCompile(`^inc-([1-9][0-9]*)$`)

type Submission struct {
	SubmittedAt time.Time `yaml:"submitted_at" json:"submitted_at"`
}
type Record struct {
	Version        int                   `yaml:"version" json:"version"`
	ID             string                `yaml:"id" json:"id"`
	Type           string                `yaml:"type" json:"type"`
	Title          string                `yaml:"title" json:"title"`
	Advisory       *string               `yaml:"advisory" json:"advisory"`
	AwareAt        time.Time             `yaml:"aware_at" json:"aware_at"`
	TimeZone       string                `yaml:"time_zone" json:"time_zone"`
	Submissions    map[string]Submission `yaml:"submissions" json:"submissions"`
	FixAvailableAt *time.Time            `yaml:"fix_available_at" json:"fix_available_at"`
	Notes          string                `yaml:"notes" json:"notes"`
}
type Stage struct {
	Name        string     `json:"name"`
	DueAt       *time.Time `json:"due_at"`
	SubmittedAt *time.Time `json:"submitted_at"`
	Overdue     bool       `json:"overdue"`
	Description string     `json:"description"`
	Draft       string     `json:"draft"`
}
type View struct {
	NextStage *Stage  `json:"next_stage"`
	Record    Record  `json:"record"`
	Awareness string  `json:"awareness"`
	Stages    []Stage `json:"stages"`
}

// ResolveZone is independent of time.Local, which Go caches before TZ may change.
func ResolveZone(tz, localtime string) *time.Location {
	if tz != "" && tz != "Local" {
		if z, e := time.LoadLocation(tz); e == nil {
			return z
		}
	}
	if link, e := filepath.EvalSymlinks(localtime); e == nil {
		if _, name, ok := strings.Cut(filepath.ToSlash(link), "/zoneinfo/"); ok && name != "Local" {
			if z, e := time.LoadLocation(name); e == nil {
				return z
			}
		}
	}
	return time.UTC
}
func LocalZone() *time.Location { return ResolveZone(os.Getenv("TZ"), "/etc/localtime") }
func ParseTime(s string, z *time.Location) (time.Time, error) {
	if t, e := time.Parse(time.RFC3339, s); e == nil {
		return t, nil
	}
	t, e := time.ParseInLocation("2006-01-02 15:04", s, z)
	if e != nil || t.Format("2006-01-02 15:04") != s {
		return time.Time{}, fmt.Errorf("use RFC 3339 with an offset or YYYY-MM-DD HH:MM in %s", z)
	}
	return t, nil
}
func FormatTime(t time.Time, zone string) string {
	z, e := time.LoadLocation(zone)
	if e != nil {
		z = time.UTC
	}
	return t.In(z).Format("2006-01-02 15:04:05 MST -07:00") + " (" + z.String() + ")"
}
func Relative(due, now time.Time) string {
	d := due.Sub(now)
	prefix := "due in "
	if d < 0 {
		prefix = "overdue by "
		d = -d
	}
	h, m := int(d/time.Hour), int(d/time.Minute)%60
	if h == 0 && m == 0 {
		return prefix + "less than 1 min"
	}
	if h == 0 {
		return fmt.Sprintf("%s%d min", prefix, m)
	}
	if m == 0 {
		return fmt.Sprintf("%s%d h", prefix, h)
	}
	return fmt.Sprintf("%s%d h %d min", prefix, h, m)
}
func nextMonth(t time.Time, z *time.Location) time.Time {
	t = t.In(z)
	last := time.Date(t.Year(), t.Month()+2, 0, 12, 0, 0, 0, z).Day()
	return time.Date(t.Year(), t.Month()+1, min(t.Day(), last), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), z)
}
func Describe(r Record, now time.Time) View {
	z, _ := time.LoadLocation(r.TimeZone)
	v := View{Record: r, Awareness: FormatTime(r.AwareAt, r.TimeZone), Stages: []Stage{}}
	for _, name := range Stages {
		s := Stage{Name: name, Draft: "cra/incidents/" + r.ID + "/" + map[string]string{"early-warning": "early-warning.md", "notification": "notification.md", "final": "final-report.md"}[name]}
		var due time.Time
		switch name {
		case "early-warning":
			due = r.AwareAt.Add(24 * time.Hour)
		case "notification":
			due = r.AwareAt.Add(72 * time.Hour)
		case "final":
			if r.Type == Exploited {
				if r.FixAvailableAt != nil {
					due = r.FixAvailableAt.Add(14 * 24 * time.Hour)
				} else {
					s.Description = "Pending: the 14-day clock starts when a fix or mitigation becomes available; record it with conformline incident fix-available " + r.ID
				}
			} else {
				basis := r.AwareAt.Add(72 * time.Hour)
				if sub, ok := r.Submissions["notification"]; ok {
					basis = sub.SubmittedAt
				} else {
					s.Description = "Provisional: based on the notification due time because its submission is not recorded. "
				}
				due = nextMonth(basis, z)
			}
		}
		if !due.IsZero() {
			due = due.In(z)
			s.DueAt = &due
			s.Description += FormatTime(due, r.TimeZone) + "; " + Relative(due, now)
		}
		if sub, ok := r.Submissions[name]; ok {
			t := sub.SubmittedAt
			s.SubmittedAt = &t
			if s.DueAt == nil {
				s.Description = "Submitted " + FormatTime(t, r.TimeZone) + ". " + s.Description
			} else {
				timing := strings.Replace(Relative(due, t), "due in ", "filed before deadline by ", 1)
				timing = strings.Replace(timing, "overdue by ", "filed late by ", 1)
				basis := ""
				if name == "final" && r.Type == Severe {
					if _, ok := r.Submissions["notification"]; !ok {
						basis = " Provisional basis: notification due time; submission not recorded."
					}
				}
				s.Description = "Submitted " + FormatTime(t, r.TimeZone) + "; " + timing + ". Deadline: " + FormatTime(due, r.TimeZone) + "." + basis
			}
		} else {
			s.Overdue = !due.IsZero() && now.After(due)
		}
		v.Stages = append(v.Stages, s)
	}
	for i := range v.Stages {
		stage := &v.Stages[i]
		if stage.SubmittedAt != nil {
			continue
		}
		if v.NextStage == nil || stage.DueAt != nil && (v.NextStage.DueAt == nil || stage.DueAt.Before(*v.NextStage.DueAt)) {
			v.NextStage = stage
		}
	}
	return v
}
func Validate(r Record) error {
	if r.Version != 1 || !validID.MatchString(r.ID) || (r.Type != Exploited && r.Type != Severe) || strings.TrimSpace(r.Title) == "" || r.AwareAt.IsZero() {
		return fmt.Errorf("invalid incident record; require version: 1, inc-N id, supported type, title and aware_at")
	}
	if r.TimeZone == "Local" {
		return fmt.Errorf("incident time_zone must be an IANA name")
	}
	if _, e := time.LoadLocation(r.TimeZone); e != nil || r.TimeZone == "" {
		return fmt.Errorf("incident time_zone must be an IANA name")
	}
	if r.FixAvailableAt != nil && (r.Type != Exploited || r.FixAvailableAt.Before(r.AwareAt)) {
		return fmt.Errorf("fix availability must be on or after awareness for an exploited vulnerability")
	}
	for stage, sub := range r.Submissions {
		if !slices.Contains(Stages, stage) || sub.SubmittedAt.IsZero() || sub.SubmittedAt.Before(r.AwareAt) {
			return fmt.Errorf("incident submissions need a valid stage and a time on or after awareness")
		}
	}
	return nil
}
func directory(root, id string) string { return filepath.Join(root, "cra", "incidents", id) }
func Load(root, id string) (Record, error) {
	var r Record
	if !validID.MatchString(id) {
		return r, os.ErrNotExist
	}
	b, e := os.ReadFile(filepath.Join(directory(root, id), "incident.yml"))
	if e != nil {
		return r, e
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if e = dec.Decode(&r); e != nil {
		return r, fmt.Errorf("cannot parse %s/incident.yml; correct the incident YAML", id)
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return r, fmt.Errorf("%s/incident.yml must contain one YAML document", id)
	}
	if e = Validate(r); e != nil {
		return r, fmt.Errorf("%s: %w", id, e)
	}
	if r.ID != id {
		return r, fmt.Errorf("incident id must match its directory %s", id)
	}
	if r.Submissions == nil {
		r.Submissions = map[string]Submission{}
	}
	return r, nil
}
func List(root string) ([]Record, error) {
	out := []Record{}
	entries, e := os.ReadDir(filepath.Join(root, "cra/incidents"))
	if os.IsNotExist(e) {
		return out, nil
	}
	if e != nil {
		return nil, e
	}
	for _, entry := range entries {
		if entry.IsDir() && validID.MatchString(entry.Name()) {
			r, e := Load(root, entry.Name())
			if e != nil {
				return nil, e
			}
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b Record) int { x, _ := strconv.Atoi(a.ID[4:]); y, _ := strconv.Atoi(b.ID[4:]); return x - y })
	return out, nil
}
func NextID(root string) (string, error) {
	records, e := List(root)
	if e != nil {
		return "", e
	}
	n := 1
	for _, r := range records {
		x, _ := strconv.Atoi(r.ID[4:])
		n = max(n, x+1)
	}
	return fmt.Sprintf("inc-%d", n), nil
}
func Save(root string, r Record) error {
	if e := Validate(r); e != nil {
		return e
	}
	b, e := yaml.Marshal(r)
	if e != nil {
		return e
	}
	dir := directory(root, r.ID)
	f, e := os.CreateTemp(dir, ".incident-*")
	if e != nil {
		return fmt.Errorf("cannot write incident.yml; check incident directory permissions")
	}
	defer os.Remove(f.Name())
	_, e = f.Write(b)
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(f.Name(), filepath.Join(dir, "incident.yml"))
	}
	if e != nil {
		return fmt.Errorf("cannot save incident.yml; check permissions and free space")
	}
	return nil
}
func Create(root string, r Record, drafts map[string]string) error {
	if e := Validate(r); e != nil {
		return e
	}
	if e := os.MkdirAll(filepath.Join(root, "cra/incidents"), 0755); e != nil {
		return fmt.Errorf("cannot create cra/incidents; check permissions")
	}
	if e := os.Mkdir(directory(root, r.ID), 0755); e != nil {
		return fmt.Errorf("cannot create incident directory; check permissions or retry with a new id")
	}
	// Only remove this newly created directory on failure; it has no maker edits yet.
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(directory(root, r.ID))
		}
	}()
	if e := Save(root, r); e != nil {
		return e
	}
	for _, name := range []string{"early-warning.md", "notification.md", "final-report.md", "user-notice.md"} {
		f, e := os.OpenFile(filepath.Join(directory(root, r.ID), name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if e != nil {
			return errors.New("cannot create incident drafts; check permissions")
		}
		_, e = io.WriteString(f, drafts[name])
		ce := f.Close()
		if e != nil || ce != nil {
			return errors.New("cannot write incident drafts; check free space")
		}
	}
	complete = true
	return nil
}
