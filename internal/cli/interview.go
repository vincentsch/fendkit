package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/vincentsch/fendkit/internal/detect"
	"github.com/vincentsch/fendkit/internal/inventory"
	"github.com/vincentsch/fendkit/internal/profile"
	"github.com/vincentsch/rungrad"
	"github.com/vincentsch/rungrad/choose"
)

type interview struct {
	f     *rungrad.Factory
	input TextInput
	p     *profile.Profile
}

func (q *interview) text(path, prompt string, value **string, fallback *string) error {
	if q.p.HasAnswer(path) {
		return nil
	}
	if !q.f.CanPrompt() {
		return nil
	}
	label := prompt + " (Enter or unknown leaves this unknown)"
	if fallback != nil {
		label = prompt + " [" + *fallback + "] (unknown clears this)"
	}
	answer, err := q.input.Ask(q.f, label)
	if err != nil {
		return err
	}
	if answer == "" && fallback != nil {
		*value = fallback
	} else if !strings.EqualFold(answer, "unknown") {
		*value = detect.String(answer)
	}
	return nil
}

func (q *interview) choice(path, prompt string, labels []string) (int, bool, error) {
	if q.p.HasAnswer(path) || !q.f.CanPrompt() {
		return 0, false, nil
	}
	options := []choose.Option{}
	for _, label := range labels {
		options = append(options, choose.Option{Label: label})
	}
	chooser := q.f.Chooser()
	// Share the text reader after it has buffered input, including scripted terminal input.
	if q.input.reader != nil {
		chooser.In = q.input.reader
	}
	n, err := chooser.Choose(prompt, options, 0)
	if err != nil {
		return 0, false, rungrad.NewError(1, "Interview canceled; run fendkit init again with --answers or --no-prompt")
	}
	return n, true, nil
}

func conductInterview(f *rungrad.Factory, p *profile.Profile, root string, product detect.Product, release *string) error {
	q := interview{f: f, p: p}
	yesNo := []struct {
		path, prompt string
		value        **bool
	}{
		{"sold", "Do you sell this product? Selling usually makes you the manufacturer.", &p.Role.Answers.Sold},
		{"paid_edition", "Do you offer a paid edition? A paid edition usually brings the product into scope.", &p.Role.Answers.PaidEdition},
		{"paid_support", "Do you charge for support? Commercial support can bring free software into scope.", &p.Role.Answers.PaidSupport},
		{"donations_only", "Is it free and open source, funded only by donations? Non-commercial open source can be outside scope.", &p.Role.Answers.DonationsOnly},
		{"hosted_only", "Is it only a hosted service with nothing to download? Hosted-only services are usually outside scope.", &p.Role.Answers.HostedOnly},
	}
	for _, item := range yesNo {
		n, asked, err := q.choice("role.answers."+item.path, item.prompt, []string{"Unknown", "Yes", "No"})
		if err != nil {
			return err
		}
		if asked && n != 0 {
			answer := n == 1
			*item.value = &answer
		}
	}
	typical := "These answers do not suggest a typical role; choose your role or leave it unknown."
	for _, item := range yesNo {
		if *item.value == nil {
			typical = "The answers are incomplete; choose your role or leave it unknown."
			break
		}
	}
	isTrue := func(v *bool) bool { return v != nil && *v }
	if isTrue(p.Role.Answers.HostedOnly) {
		typical = "A hosted-only service is usually outside scope."
	} else if isTrue(p.Role.Answers.Sold) || isTrue(p.Role.Answers.PaidEdition) || isTrue(p.Role.Answers.PaidSupport) {
		typical = "Selling the product, a paid edition or support usually makes you the manufacturer."
	} else if isTrue(p.Role.Answers.DonationsOnly) {
		typical = "Non-commercial free and open source software can be outside scope; a supporting organisation may be an open-source steward."
	}
	n, asked, err := q.choice("role.answer", typical+" You decide which role applies.", []string{"unknown", "manufacturer", "open-source-steward", "not-in-scope"})
	if err != nil {
		return err
	}
	if asked {
		p.Role.Answer = []string{"unknown", "manufacturer", "open-source-steward", "not-in-scope"}[n]
	}
	defaults := contactDefaults(root, product)
	fields := []struct {
		path, prompt string
		value        **string
		fallback     *string
	}{
		{"manufacturer.name", "Manufacturer name", &p.Manufacturer.Name, defaults.Manufacturer.Name},
		{"manufacturer.address", "Manufacturer postal address", &p.Manufacturer.Address, nil},
		{"manufacturer.website", "Manufacturer website", &p.Manufacturer.Website, defaults.Manufacturer.Website},
		{"security_contact.email", "Email for vulnerability reports", &p.SecurityContact.Email, defaults.SecurityContact.Email},
		{"security_contact.url", "HTTPS page for vulnerability reports", &p.SecurityContact.URL, defaults.SecurityContact.URL},
		{"security_contact.policy_url", "Published disclosure policy HTTPS URL", &p.SecurityContact.PolicyURL, nil},
		{"support.end", "Security support end date (YYYY-MM-DD). Art. 13(8) calls for at least five years unless expected use is shorter", &p.Support.End, nil},
		{"support.versions", "Version line covered by this support period", &p.Support.Versions, nil},
		{"support.updates", "How users receive security updates", &p.Support.Updates, nil},
	}
	if p.Role.Answer == "not-in-scope" {
		fields = nil
	}
	for _, item := range fields {
		for {
			if err := q.text(item.path, item.prompt, item.value, item.fallback); err != nil {
				return err
			}
			if item.path != "support.end" || *item.value == nil {
				break
			}
			if _, err := time.Parse("2006-01-02", **item.value); err == nil {
				break
			}
			if p.HasAnswer(item.path) || !f.CanPrompt() {
				return rungrad.NewError(1, "support.end: use YYYY-MM-DD or null in the answers file")
			}
			fmt.Fprintln(f.Stderr, "Use YYYY-MM-DD, or unknown.")
			*item.value = nil
		}
	}
	if p.Role.Answer != "not-in-scope" && !p.HasAnswer("classification.categories") && !p.HasAnswer("classification.answer") && f.CanPrompt() {
		fmt.Fprintln(f.Stderr, "Is the core function of your product one of these? Implementing Regulation (EU) 2025/2392 describes the categories in detail. A feature inside a product does not make the whole product important.")
		last := ""
		for i, c := range profile.Categories() {
			group := "Class I (Annex III, part I)"
			if strings.HasPrefix(c.ID, "ii-") {
				group = "Class II (Annex III, part II)"
			}
			if strings.HasPrefix(c.ID, "iv-") {
				group = "Critical (Annex IV)"
			}
			if group != last {
				fmt.Fprintln(f.Stderr, group)
				last = group
			}
			fmt.Fprintf(f.Stderr, "%d. %s\n   %s Examples: %s.\n", i+1, c.Name, c.Explanation, strings.Join(c.Examples, "; "))
		}
		for {
			answer, err := q.input.Ask(f, "Core function categories (numbers separated by commas; 0 for none; Enter for unknown)")
			if err != nil {
				return err
			}
			ids, class, err := profile.ParseSelection(answer)
			if err != nil {
				fmt.Fprintln(f.Stderr, err)
				continue
			}
			p.Classification.Categories, p.Classification.Answer = ids, class
			break
		}
	} else if p.HasAnswer("classification.categories") && p.Classification.Categories != nil {
		class, err := profile.Classify(p.Classification.Categories)
		if err != nil {
			return rungrad.NewError(1, err.Error())
		}
		if p.HasAnswer("classification.answer") && p.Classification.Answer != class {
			return rungrad.NewError(1, "classification.answer conflicts with categories; use the highest selected class")
		}
		p.Classification.Answer = class
	}
	if release != nil {
		p.Product.Release = release
	} else {
		for {
			if err := q.text("product.release", "Release ZIP or folder, relative to --dir", &p.Product.Release, nil); err != nil {
				return err
			}
			if p.Product.Release == nil || p.HasAnswer("product.release") || !f.CanPrompt() {
				break
			}
			path := *p.Product.Release
			if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
				home, err := os.UserHomeDir()
				if err != nil {
					fmt.Fprintln(f.Stderr, "Cannot find your home folder; enter an absolute path, a path relative to --dir, or unknown.")
					p.Product.Release = nil
					continue
				}
				path = filepath.Join(home, path[2:])
			}
			if err := inventory.ValidateRelease(root, product, path); err != nil {
				fmt.Fprintln(f.Stderr, err.Error()+"; enter another release path or unknown.")
				p.Product.Release = nil
				continue
			}
			p.Product.Release = &path
			break
		}
	}
	if p.Product.Release != nil {
		path := *p.Product.Release
		if filepath.IsAbs(path) {
			abs, err := filepath.Abs(root)
			if err != nil {
				return err
			}
			path = inventory.RelativeOrAbsolute(abs, path)
		}
		dir, base := filepath.Split(path)
		if product.Version != nil {
			base = strings.Replace(base, *product.Version, "{version}", 1)
		}
		p.Product.Release = detect.String(filepath.ToSlash(filepath.Join(dir, base)))
	}
	date := time.Now().Format("2006-01-02")
	if !p.HasAnswer("role.decided_on") && p.Role.DecidedOn == nil && p.Role.Answer != "" && p.Role.Answer != "unknown" {
		p.Role.DecidedOn = &date
	}
	if !p.HasAnswer("classification.decided_on") && p.Classification.DecidedOn == nil && p.Classification.Answer != "" && p.Classification.Answer != "unknown" {
		p.Classification.DecidedOn = &date
	}
	return nil
}

func contactDefaults(root string, product detect.Product) *profile.Profile {
	p := &profile.Profile{}
	header := func(b []byte, key string) *string {
		re := regexp.MustCompile("(?mi)^[\\s/*#]*" + regexp.QuoteMeta(key) + ":\\s*([^\\r\\n]*)")
		m := re.FindSubmatch(b)
		if len(m) < 2 {
			return nil
		}
		return detect.String(strings.TrimSpace(strings.TrimSuffix(string(m[1]), "*/")))
	}
	for _, file := range product.Evidence {
		b, _ := os.ReadFile(filepath.Join(root, file))
		if name := header(b, "Author"); name != nil {
			p.Manufacturer.Name = name
		}
		if site := header(b, "Author URI"); site != nil {
			p.Manufacturer.Website = site
		}
	}
	b, _ := os.ReadFile(filepath.Join(root, "composer.json"))
	var composer struct {
		Homepage string
		Authors  []struct{ Name, Homepage string }
	}
	if json.Unmarshal(b, &composer) == nil {
		if len(composer.Authors) > 0 && p.Manufacturer.Name == nil {
			p.Manufacturer.Name = detect.String(composer.Authors[0].Name)
		}
		if p.Manufacturer.Website == nil {
			p.Manufacturer.Website = detect.String(composer.Homepage)
		}
	}
	b, _ = os.ReadFile(filepath.Join(root, "SECURITY.md"))
	if m := regexp.MustCompile(`[a-zA-Z0-9.!#$%&'*+/=?^_{|}~-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`).Find(b); m != nil {
		p.SecurityContact.Email = detect.String(string(m))
	}
	if m := regexp.MustCompile(`https://[^\s<>\[\]()]+`).Find(b); m != nil {
		p.SecurityContact.URL = detect.String(strings.TrimRight(string(m), ".,"))
	}
	return p
}
