package docs

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"io/fs"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/vincentsch/conformline/internal/detect"
	"github.com/vincentsch/conformline/internal/profile"
	"github.com/vincentsch/conformline/internal/version"
	"gopkg.in/yaml.v3"
)

//go:embed templates/*
var templates embed.FS

var Files = []string{"SECURITY.md", "cra/security.txt", "cra/disclosure-policy.md", "cra/support-period.md", "cra/user-information.md", "cra/risk-assessment.md", "cra/technical-documentation.md", "cra/eu-declaration-of-conformity.md", "cra/incident-checklist.md"}

type Result struct {
	Created  []string `json:"created"`
	Existing []string `json:"existing"`
	DryRun   bool     `json:"dry_run"`
	Message  string   `json:"message,omitempty"`
}
type indexEntry struct{ Path, Label, Status string }
type data struct {
	ToolVersion     string
	P               *profile.Profile
	Now             time.Time
	ProductVersion  *string
	Documents       []indexEntry
	Reports         []indexEntry
	Message         string
	Next            []string
	ScanLabel       string
	StatusEvaluated bool
}

func fact(value *string, hint string) string {
	if value == nil || strings.TrimSpace(*value) == "" {
		return "[[" + hint + "]]"
	}
	return *value
}
func https(value *string) string {
	if value == nil {
		return ""
	}
	u, err := url.Parse(*value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return ""
	}
	return u.String()
}
func securityFields(d data) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# status: draft\n# reviewed_by:\n# reviewed_on:\n# conformline: %s\n", version.Version)
	if d.P.SecurityContact.Email != nil {
		address, err := mail.ParseAddress(*d.P.SecurityContact.Email)
		if err == nil {
			fmt.Fprintln(&b, "Contact: mailto:"+address.Address)
		} else {
			fmt.Fprintln(&b, "# Contact: [[valid security email as mailto: URI]]")
		}
	} else {
		fmt.Fprintln(&b, "# Contact: [[security email as mailto: URI]]")
	}
	if contact := https(d.P.SecurityContact.URL); contact != "" {
		fmt.Fprintln(&b, "Contact: "+contact)
	} else {
		fmt.Fprintln(&b, "# Contact: [[HTTPS vulnerability reporting URL]]")
	}
	fmt.Fprintln(&b, "Expires: "+d.Now.AddDate(0, 0, 364).Format(time.RFC3339))
	if policy := https(d.P.SecurityContact.PolicyURL); policy != "" {
		fmt.Fprintln(&b, "Policy: "+policy)
	} else {
		fmt.Fprintln(&b, "# Policy: [[published HTTPS disclosure policy URL]]")
	}
	fmt.Fprintln(&b, "Preferred-Languages: en")
	if site := https(d.P.Manufacturer.Website); site != "" {
		u, _ := url.Parse(site)
		u.Path = "/.well-known/security.txt"
		u.RawQuery = ""
		u.Fragment = ""
		fmt.Fprintln(&b, "Canonical: "+u.String())
	} else {
		fmt.Fprintln(&b, "# Canonical: [[https://your-domain/.well-known/security.txt]]")
	}
	fmt.Fprintln(&b, "# Review and publish this draft before use. Requirement: Annex I Part II point 6; RFC 9116.")
	return b.String()
}

func Generate(root string, p *profile.Profile, now time.Time, dry bool) (Result, error) {
	r := Result{Created: []string{}, Existing: []string{}, DryRun: dry}
	d := documentData(root, p, now)
	r.Message = d.Message
	funcs := template.FuncMap{"fact": fact, "securityFields": securityFields}
	for _, file := range Files {
		path := filepath.Join(root, filepath.FromSlash(file))
		_, err := os.Lstat(path)
		if err == nil {
			r.Existing = append(r.Existing, file)
			continue
		}
		if !os.IsNotExist(err) {
			return r, fmt.Errorf("cannot inspect %s; check project permissions", file)
		}
		if p.Role.Answer == "not-in-scope" {
			continue
		}
		name := filepath.Base(file) + ".tmpl"
		content, err := renderTemplate(name, funcs, d)
		if err != nil {
			return r, err
		}
		if !dry {
			if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return r, fmt.Errorf("cannot create directory for %s; check project permissions", file)
			}
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
			if os.IsExist(err) {
				r.Existing = append(r.Existing, file)
				continue
			}
			if err != nil {
				return r, fmt.Errorf("cannot create %s; check project permissions", file)
			}
			_, writeErr := f.Write(content)
			closeErr := f.Close()
			if writeErr != nil || closeErr != nil {
				return r, fmt.Errorf("cannot write %s; check free space and permissions", file)
			}
		}
		r.Created = append(r.Created, file)
	}
	return r, WriteIndex(root, p, now, nil, "", dry)
}

func documentData(root string, p *profile.Profile, now time.Time) data {
	d := data{P: p, Now: now, ProductVersion: p.Product.Version}
	// Detection supplies the current version when there is no explicit override.
	if d.ProductVersion == nil {
		if product, err := detect.Detect(root); err == nil {
			d.ProductVersion = product.Version
		}
	}
	// Saved reports can still supply facts when the source no longer identifies a version.
	if b, err := os.ReadFile(filepath.Join(root, "cra/reports/inventory.json")); err == nil {
		var saved struct {
			Product   struct{ Version *string }
			ScannedAt time.Time `json:"scanned_at"`
		}
		if json.Unmarshal(b, &saved) == nil && d.ProductVersion == nil {
			d.ProductVersion = saved.Product.Version
		}
	}
	if p.Role.Answer == "not-in-scope" {
		d.Message = "Your recorded role is not-in-scope. Manufacturer documents are skipped; the decision and scan stay."
	} else if p.Role.Answer == "open-source-steward" {
		d.Message = "Conformline v0.1 follows the manufacturer preparation steps. It does not assess steward obligations under Art. 24."
	} else if p.Role.Answer == "unknown" {
		d.Message = "Your role needs your decision first. These manufacturer documents remain preparation drafts."
	}
	return d
}

// WriteIndex preserves the preparation guidance and adds the evaluated next actions.
func WriteIndex(root string, p *profile.Profile, now time.Time, next []string, scanLabel string, dry bool) error {
	d := documentData(root, p, now)
	d.Next = next
	d.ScanLabel = scanLabel
	d.StatusEvaluated = next != nil
	for _, file := range Files {
		path := filepath.Join(root, filepath.FromSlash(file))
		if _, err := os.Lstat(path); err == nil {
			link := filepath.Base(file)
			if file == "SECURITY.md" {
				link = "../SECURITY.md"
			}
			d.Documents = append(d.Documents, indexEntry{link, file, documentStatus(path)})
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("cannot inspect %s; check project permissions", file)
		}
	}
	for _, file := range []string{"inventory.json", "sbom.cdx.json", "vulnerabilities.json", "vulnerabilities.md", "vex.openvex.json", "status.md", "status.html"} {
		path := filepath.Join(root, "cra/reports", file)
		if _, err := os.Stat(path); err == nil {
			label := reportDescription(path)
			d.Reports = append(d.Reports, indexEntry{"reports/" + file, file, label})
		}
	}
	b, err := renderTemplate("README.md.tmpl", template.FuncMap{"fact": fact, "escape": markdownText}, d)
	if err != nil {
		return err
	}
	if !dry {
		if err = os.MkdirAll(filepath.Join(root, "cra"), 0755); err != nil {
			return fmt.Errorf("cannot create cra; check project permissions")
		}
		// Replace the index through a temporary file, leaving symlink targets untouched.
		f, err := os.CreateTemp(filepath.Join(root, "cra"), ".index-*")
		if err != nil {
			return fmt.Errorf("cannot write cra/README.md; check project permissions")
		}
		defer os.Remove(f.Name())
		_, err = f.Write(b)
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Chmod(f.Name(), 0644)
		}
		if err == nil {
			err = os.Rename(f.Name(), filepath.Join(root, "cra/README.md"))
		}
		if err != nil {
			return fmt.Errorf("cannot replace cra/README.md; check project permissions")
		}
	}
	return nil
}
func markdownText(s string) string {
	return strings.NewReplacer("|", "&#124;", "\n", "<br>", "\r", "", "[", "&#91;", "]", "&#93;", "`", "&#96;", "*", "&#42;", "_", "&#95;").Replace(html.EscapeString(s))
}

func renderTemplate(name string, funcs template.FuncMap, d data) ([]byte, error) {
	b, err := fs.ReadFile(templates, "templates/"+name)
	if err != nil {
		return nil, err
	}
	t, err := template.New(name).Funcs(funcs).Parse(string(b))
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	d.ToolVersion = version.Version
	err = t.Execute(&out, d)
	return out.Bytes(), err
}
func documentStatus(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "unreadable; check permissions"
	}
	text := string(b)
	if strings.HasSuffix(path, "security.txt") {
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "# status:") {
				return strings.TrimSpace(strings.TrimPrefix(line, "# status:"))
			}
		}
	} else if strings.HasPrefix(text, "---\n") {
		if end := strings.Index(text[4:], "\n---"); end >= 0 {
			var meta struct{ Status string }
			if yaml.Unmarshal([]byte(text[4:4+end]), &meta) == nil && meta.Status != "" {
				return meta.Status
			}
		}
	}
	return "existing; review metadata not set"
}

// Report dates come from report content, never from filesystem timestamps.
func reportDescription(path string) string {
	if filepath.Base(path) == "status.md" || filepath.Base(path) == "status.html" {
		b, err := os.ReadFile(filepath.Join(filepath.Dir(path), "status.md"))
		if err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "Scan: ") {
					stamp, _, _ := strings.Cut(strings.TrimPrefix(line, "Scan: "), ",")
					return "Recorded scan: " + stamp
				}
			}
		}
		return "Saved status report; scan date unavailable"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "Saved report; unreadable"
	}
	var report struct {
		ScannedAt time.Time `json:"scanned_at"`
		Complete  *bool     `json:"complete"`
		Metadata  struct {
			Timestamp  time.Time                      `json:"timestamp"`
			Properties []struct{ Name, Value string } `json:"properties"`
		} `json:"metadata"`
		Statements []struct {
			Timestamp time.Time `json:"timestamp"`
		} `json:"statements"`
	}
	date := time.Time{}
	incomplete := false
	if strings.HasSuffix(path, ".json") && json.Unmarshal(b, &report) == nil {
		date = report.ScannedAt
		incomplete = report.Complete != nil && !*report.Complete
		if date.IsZero() {
			date = report.Metadata.Timestamp
		}
		for _, prop := range report.Metadata.Properties {
			if prop.Name == "conformline:complete" && prop.Value == "false" {
				incomplete = true
			}
		}
		if date.IsZero() {
			for _, statement := range report.Statements {
				if statement.Timestamp.After(date) {
					date = statement.Timestamp
				}
			}
		}
	} else if _, tail, ok := strings.Cut(string(b), "Scanned at "); ok {
		stamp, _, _ := strings.Cut(tail, ".\n")
		date, _ = time.Parse(time.RFC3339, stamp)
		incomplete = strings.Contains(string(b), "is **incomplete**")
	}
	if date.IsZero() {
		return "Saved report; date unavailable"
	}
	label := "Recorded " + date.Format(time.RFC3339)
	if incomplete {
		label += "; incomplete"
	}
	return label
}
