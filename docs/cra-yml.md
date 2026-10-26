# cra.yml

`cra.yml` is where Fendkit, a free, open-source CLI for Cyber Resilience Act
evidence, keeps a software maker's answers and decisions. It is a versioned
YAML file in your product root. Commit it with the product. Init
combines the detected facts with your answers and writes the file. Later
commands read it and do not repeat the interview. Init refuses to replace an
existing profile. An invalid field or value stops the command with an error.

## Partial answers and unknowns

An answers file uses the same schema and starts with `version: 1`. Fields you
leave out come from detection or from the interview. With `--no-prompt`,
decisions you did not answer stay unknown. Put the file outside your product
repository and remove it afterwards. See the
[tested partial answers example](../AGENTS.md#partial-answers-example).

```bash
fendkit init --no-prompt --answers /tmp/maker-answers.yml --release ../dist/plugin.zip
```

The file has to hold your own answers. `classification.categories: null`
means unknown. `[]` records on purpose that none of the Annex III/IV
categories applies, so never write `[]` for a decision you have not made. If
you give categories, init records the highest class among them. The answer
may stay out of the file. If you give both, they have to agree, or init stops
and names the field. An `unknown` or null answer goes with null or omitted
categories. When you decide in the interview that no listed category applies,
init saves `default` with `[]`. An existing profile with only an answer does
not need categories added.

Init keeps the decision dates and reviewer names you supply. An explicit null
date stays null. Only a decided answer without a date gets today's date. Unknown or
unanswered decisions stay without a date. Later scan, docs and check keep
unknown decisions and do not repeat the interview.

## Supported fields

Text and booleans may be null when unknown. Dates use YYYY-MM-DD.

| Section | Fields and accepted values |
| --- | --- |
| `version` | Required integer `1`. |
| `product` | `name`, `type`, `version`, `description`, `release`, `distribution` (list of text). Types: `wordpress-plugin`, `wordpress-theme`, `composer-package`, `npm-package`, `application`, `other`. |
| `manufacturer` | `name`, `address`, `website`. |
| `role` | `answer`: `manufacturer`, `open-source-steward`, `not-in-scope`, `unknown`; `answers` mapping below; `decided_by`, `decided_on`. |
| `role.answers` | `sold`, `paid_edition`, `paid_support`, `donations_only`, `hosted_only`, all nullable booleans. |
| `classification` | `answer`: `default`, `important-class-i`, `important-class-ii`, `critical`, `unknown`; `categories`: list of IDs from init's Annex III/IV list or null; `decided_by`, `decided_on`, `note`. |
| `security_contact` | `email`, `url`, `policy_url`. Drafts need valid addresses and HTTPS links where they ask for them. |
| `support` | `end` (date), `versions` (text version line), `updates` (text method). |
| `components` | List of manual component mappings, described below. |
| `triage` | List of decisions per advisory and component version, described below. |

Release paths and patterns count from the project root, even for sibling
paths. `--release` overrides the saved path for one scan. Change the path in
the profile when later scans should use another release. An unknown product
version needs a known version before the evidence can be current. See
[inventory](inventory.md). A release on another Windows drive is kept as an
absolute path. That path works only on that machine and can show a personal
directory name when you share the reports.

## Manual components

Each component takes `name`, `version`, `ecosystem`, `purl`, `path`, `shipped`
and `note`. Use the ecosystem `npm` or `composer` to get vulnerability
lookups. Leave `shipped` out to keep what detection found. `true` and `false`
are explicit decisions, and `shipped: null` marks that occurrence as unknown
on purpose. Init and triage keep these values and your comments. When the
same component appears more than once, one shipped copy makes the group
shipped. Otherwise one unknown copy makes the group unknown. Known versions
and purls have to come from evidence.

To add a library that detection did not recognise, leave `path` out. That
field only matches an occurrence that was already detected. Put the file
location and the shipping evidence in `note`. This example leaves the version
unknown until you have verified it:

```yaml
components:
  - name: widget
    version: null
    ecosystem: npm
    purl: pkg:npm/widget
    shipped: true
    note: "assets/js/widget.min.js is present in the shipped ZIP; version not yet verified"
```

To correct an occurrence that was detected, use its exact path from
`cra/reports/inventory.json`. For example, after you verified the version in
the shipped banner:

```yaml
components:
  - name: moment
    version: 2.24.0
    ecosystem: npm
    purl: pkg:npm/moment@2.24.0
    path: assets/js/vendor/moment.min.js
    shipped: true
    note: Version verified from the shipped banner
```

Manual entries add to or correct the detected evidence. They do not make an
unsupported format covered and do not prove that there are no other bundles.

## Saved triage

Prefer [the triage command](vulnerabilities.md#decide-what-a-finding-means-for-this-product).
Each record has `advisory`, `component` (the exact purl with version),
`status`, `justification`, `reason` and `decided_on`. The status is
`affected`, `not_affected`, `fixed` or `under_investigation`. All need a
reason and a decision date. `not_affected` also needs a supported OpenVEX
justification. See [the generated reference](reference/fendkit_triage.md)
for the values.

When triage updates the profile, it keeps your YAML comments. Scan and docs do
not save new answers. Your existing documents also stay untouched. Review
changed facts yourself with [the documents guide](documents.md).
