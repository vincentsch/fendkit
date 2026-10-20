# Complete and review the drafts

`conformline docs` creates missing documents using the saved profile. It never
replaces existing maker documents, including edited drafts. It refreshes only
`cra/README.md`, the index of next actions, documents and reports.
Changed profile answers do not rewrite old drafts: update those facts yourself.

## What each file needs

| File | What you complete |
| --- | --- |
| `SECURITY.md` | Public security contact, supported versions and reporting instructions. |
| `cra/security.txt` | Contact, expiry, policy and canonical URLs; deploy as described below. |
| `cra/disclosure-policy.md` | How you receive, investigate and disclose vulnerabilities (Annex I Part II). |
| `cra/support-period.md` | Security support end, version line, update method and rationale (Article 13(8)). |
| `cra/user-information.md` | Intended use, secure setup, updates, risks and removal instructions (Annex II). |
| `cra/risk-assessment.md` | Product-specific threats, controls and residual risks (Article 13 and Annex I). |
| `cra/technical-documentation.md` | Architecture, development, tests and vulnerability handling evidence (Annex VII). |
| `cra/eu-declaration-of-conformity.md` | Product identity, applicable references and assessment details (Annex V). Keep it an unsigned draft until the responsible person completes the legal process. |
| `cra/incident-checklist.md` | Reporting responsibilities, access and live-form checks (Article 14). |

For a recorded `not-in-scope` role, manufacturer drafts are skipped. Existing
files are preserved. Steward mode does not assess Article 24 obligations.
See [role and scope](cra-for-plugin-makers.md).

## Record your review

Fill the `[[placeholders]]`, check the substance and record the reviewer.
Markdown uses YAML front matter:

```yaml
---
status: reviewed
reviewed_by: Your Name
reviewed_on: "2026-10-20"
---
```

Use the date you reviewed it. security.txt uses the same three fields as
`# status:`, `# reviewed_by:` and `# reviewed_on:` comments. The checker looks
for a nonblank reviewer, valid date and no placeholders. Expired security.txt
still needs attention. A marker does not prove the review was adequate.
Agents must leave review decisions to the maker. Review metadata does not sign
or final-date the declaration. All generated documents begin as drafts;
Conformline gives no legal advice.

## Publish security.txt

Review `Contact`, `Expires`, `Policy` and `Canonical` in `cra/security.txt`.
Serve the reviewed file over HTTPS at `/.well-known/security.txt` on your
product's website, following [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116).
Keep its policy URL reachable and renew it before expiry. Conformline cannot
check deployment from local files. Root SECURITY.md also needs your review
and publication where users find your project.

After edits, run `conformline docs` to refresh the index and
`conformline check` for [status and next actions](status-items.md).
[Incident drafts](incidents.md) live separately and also require human review.
