package incident

import (
	"fmt"
	"strings"

	"github.com/vincentsch/conformline/internal/detect"
	"github.com/vincentsch/conformline/internal/profile"
	"github.com/vincentsch/conformline/internal/vulns"
)

func field(p *string, prompt string) string {
	if p == nil || strings.TrimSpace(*p) == "" {
		return "[[" + prompt + "]]"
	}
	return *p
}

// Drafts uses only the profile, detected product and saved advisory findings.
// Deadlines belong in Describe, never in maker-owned filing text.
func Drafts(r Record, p *profile.Profile, product detect.Product, findings []vulns.Finding) map[string]string {
	if p.Product.Name != nil {
		product.Name = p.Product.Name
	}
	if p.Product.Version != nil {
		product.Version = p.Product.Version
	}
	summary := "[[Summarise the facts known so far.]]"
	advisory := "[[Advisory identifiers, if any.]]"
	if r.Advisory != nil {
		advisory = *r.Advisory
		summaries := []string{}
		for _, f := range findings {
			matched := false
			for _, id := range f.IDs {
				matched = matched || id == *r.Advisory
			}
			if !matched {
				continue
			}
			text := fmt.Sprintf("Component: %s %s\n\n", f.Component.Name, field(f.Component.Version, "Component version"))
			for _, a := range f.Advisories {
				text += fmt.Sprintf("%s: %s\n\nSeverity from saved advisory: %s\n\nFixed versions from saved advisory: %s\n\n", a.ID, a.Summary, vulns.Rating(a, f.Component), strings.Join(vulns.Fixed(a, f.Component), ", "))
				for _, ref := range a.References {
					text += ref.URL + "\n\n"
				}
			}
			summaries = append(summaries, text)
		}
		if len(summaries) > 0 {
			summary = strings.Join(summaries, "\n") + "\n[[Verify applicability and add incident-specific facts.]]"
		}
	}
	header := fmt.Sprintf("Awareness time: %s\n\nCurrent deadlines: `conformline incident show %s`.\n\nCheck the live form in ENISA's Single Reporting Platform before filing.\n\n%s\n\n", FormatTime(r.AwareAt, r.TimeZone), r.ID, Legal)
	common := fmt.Sprintf("## Type and level\n\n%s; [[Reporting level and severity assessment.]]\n\n## Title\n\n%s\n\n## Manufacturer\n\n%s\n\n%s\n\n%s\n\n## Product name and version\n\n%s %s\n\n## Summary and advisory\n\n%s\n\n%s\n\n## Suspected unlawful or malicious acts\n\n[[State whether suspected and what is known.]]\n\n## Member States affected or where the product is available\n\n[[List Member States where known, distinguishing availability and affected users.]]\n\n", r.Type, r.Title, field(p.Manufacturer.Name, "Manufacturer name"), field(p.Manufacturer.Address, "Manufacturer address"), field(p.Manufacturer.Website, "Manufacturer website"), field(product.Name, "Product name"), field(product.Version, "Product version"), advisory, summary)
	notification := fmt.Sprintf("## Nature and initial assessment\n\n[[Describe the vulnerability or incident, severity and initial impact.]]\n\n## Exploit details\n\n[[Describe known exploitation; mark facts that remain unknown.]]\n\n## Corrective or mitigating measures\n\n[[Describe measures taken and planned, including security updates.]]\n\n## Measures users can take\n\n[[Give actionable protective steps.]]\n\n## Product category under Annex III/IV\n\nRecorded classification: %s\n\nRecorded categories: %s\n\n[[Confirm the relevant product category.]]\n\n## Information sensitivity\n\n[[Explain sensitivity and disclosure restrictions.]]\n\n", p.Classification.Answer, strings.Join(p.Classification.Categories, ", "))
	final := "## Detailed description, severity and impact\n\n[[Describe the vulnerability, its severity and impact.]]\n\n## Malicious actor\n\n[[Give available information about any malicious actor; state when unknown.]]\n\n## Security update or other measures\n\n[[Describe the available security update or corrective or mitigating measures and how to obtain them.]]\n\nRequirement: Art. 14(2)(c).\n"
	if r.Type == Severe {
		final = "## Detailed description, severity and impact\n\n[[Describe the incident, severity and impact.]]\n\n## Threat or root cause\n\n[[Explain the type of threat or likely root cause.]]\n\n## Applied and ongoing mitigation\n\n[[Describe mitigation measures applied and still ongoing.]]\n\nRequirement: Art. 14(4)(c).\n"
	}
	return map[string]string{
		"early-warning.md": header + "# Early warning\n\n" + common + "Requirement: Art. 14(2)(a), 14(4)(a).\n",
		"notification.md":  header + "# Notification\n\n" + common + notification + "Requirement: Art. 14(2)(b), 14(4)(b).\n",
		"final-report.md":  header + "# Final report\n\n" + common + final,
		"user-notice.md":   header + "# User notice\n\n" + common + "## Who should receive this notice\n\n[[Inform affected users and, where appropriate, all users without undue delay. Record channels and publication time.]]\n\n## What happened and what you can do\n\n[[Explain the vulnerability or incident and the protective steps and updates users can apply. Use structured, machine-readable information where appropriate.]]\n\n## Contact\n\n" + field(p.SecurityContact.Email, "Security contact email") + "\n\n" + field(p.SecurityContact.URL, "Security contact URL") + "\n\nRequirement: Art. 14(8).\n",
	}
}
