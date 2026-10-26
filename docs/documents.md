# Draft documents

`fendkit docs` creates the draft documents a software maker needs for the
Cyber Resilience Act. It is part of Fendkit, a free, open-source CLI. The
command creates the documents that are missing, from the answers saved in
`cra.yml`. It never
replaces a document you already have, including an edited draft. The only
file it refreshes is `cra/README.md`, the index of next actions, documents and
reports. If you change an answer later, the old drafts stay as they are.
Update those facts in the documents yourself.

## What each file needs

| File | What you complete |
| --- | --- |
| `SECURITY.md` | Your public security contact, the supported versions and how to report a vulnerability. |
| `cra/security.txt` | Contact, expiry, policy and canonical URLs. Deploy it as described below. |
| `cra/disclosure-policy.md` | How you receive, investigate and disclose vulnerabilities (Annex I Part II). |
| `cra/support-period.md` | When security support ends, which version line gets it, how you deliver updates and why you chose that period (Article 13(8)). |
| `cra/user-information.md` | Intended use, secure setup, updates, risks and how to remove the product (Annex II). |
| `cra/risk-assessment.md` | The threats to your product, your controls and the risks that remain (Article 13 and Annex I). |
| `cra/technical-documentation.md` | Architecture, development, tests and your vulnerability handling (Annex VII). |
| `cra/eu-declaration-of-conformity.md` | Product identity, the references that apply and the assessment details (Annex V). It stays an unsigned draft until the responsible person completes the legal process. |
| `cra/incident-checklist.md` | Who reports, who has access and a check of the live form (Article 14). |

With the role `not-in-scope`, Fendkit skips the manufacturer drafts and keeps
existing files. For an open-source steward it does not assess the Article 24
obligations. See [role and scope](cra-for-plugin-makers.md).

## Record your review

Replace every `[[placeholder]]` with facts about your product and check that
the document describes what you do. When you have reviewed it, add your name
and the date. Markdown files keep these fields in YAML front matter at the
top:

```yaml
---
status: reviewed
reviewed_by: Your Name
reviewed_on: "2026-10-20"
---
```

security.txt has the same three fields as
`# status:`, `# reviewed_by:` and `# reviewed_on:` comments. The checker looks
for a non-blank reviewer, a valid date and no placeholders. An expired
security.txt still needs attention. The marker does not prove that your
review was good enough. Review the documents yourself instead of letting an
agent mark them reviewed. The review fields do not sign the declaration and do
not give it an issue date. Fendkit gives no legal advice.

## Publish security.txt

Check `Contact`, `Expires`, `Policy` and `Canonical` in `cra/security.txt`.
Serve the reviewed file over HTTPS at `/.well-known/security.txt` on your
product's website, as [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)
describes. Keep the policy URL reachable and renew the file before it
expires. Fendkit cannot check from local files whether you deployed it. The
root `SECURITY.md` also needs your review, and it belongs where your users
find your project.

After your edits, run `fendkit docs` to refresh the index and `fendkit check`
for the [status and next actions](status-items.md). The
[incident drafts](incidents.md) live in their own folder and also need a
person's review.
