# Keep decisions in cra.yml

`cra.yml` is a versioned YAML record in your product root. Commit it with the
product. Init detects product facts and merges your partial answers; later
scan/docs/check read it. Init refuses to replace an existing profile.
The reader rejects unknown fields, invalid types and unsupported schema versions.

## Partial answers and unknowns

An answers file uses the same schema, starting with `version: 1`. Omitted fields
remain for detection or the interview. With `--no-prompt`, unanswered decisions
stay unknown. Use a temporary file outside your product repository, then remove
it. See the [tested partial answers example](../AGENTS.md#partial-answers-example).

```bash
fendkit init --no-prompt --answers /tmp/maker-answers.yml --release ../dist/plugin.zip
```

The file must contain your own answers, not the example maker's details.
`classification.categories: null` means unknown; `[]` deliberately records
that none of the Annex III/IV categories apply. Never substitute `[]` for an
unknown decision. Init derives the highest class from explicitly selected
categories. Keep an unknown `classification.answer` as `unknown` with null
categories. An explicit none decision becomes `default` with `[]`.
Explicit decided answers must match the highest selected class (or `default`
for `[]`). Explicit `unknown` or null answers require null or omitted categories;
they cannot coexist with a selected list, even `[]`. Loading and saving reject
conflicts with a field diagnostic. Categories-only partial answers preserve the
omitted answer through saves; init then records the derived class. Existing
answer-only profiles need no category backfill.

Init preserves supplied decision dates, explicit null dates and reviewer names.
Only an omitted date for a decided answer is filled with today’s date. Unknown
or unanswered decisions remain undated.
Later scan/docs/check preserve unknown decisions without repeating the interview.

## Supported fields

Text may be null when unknown. Dates use YYYY-MM-DD. Booleans use `true`,
`false` or `null`. Lists are YAML sequences, not comma-separated strings.

| Section | Fields and accepted values |
| --- | --- |
| `version` | Required integer `1`. |
| `product` | `name`, `type`, `version`, `description`, `release`, `distribution` (list of text). Types: `wordpress-plugin`, `wordpress-theme`, `composer-package`, `npm-package`, `application`, `other`. |
| `manufacturer` | `name`, `address`, `website`. |
| `role` | `answer`: `manufacturer`, `open-source-steward`, `not-in-scope`, `unknown`; `answers` mapping below; `decided_by`, `decided_on`. |
| `role.answers` | `sold`, `paid_edition`, `paid_support`, `donations_only`, `hosted_only`, all nullable booleans. |
| `classification` | `answer`: `default`, `important-class-i`, `important-class-ii`, `critical`, `unknown`; `categories`: list of IDs from init's Annex III/IV list or null; `decided_by`, `decided_on`, `note`. |
| `security_contact` | `email`, `url`, `policy_url`. Use real contact details; drafts require valid addresses/HTTPS links where appropriate. |
| `support` | `end` (date), `versions` (text version line), `updates` (text method). |
| `components` | List of manual component mappings described below. |
| `triage` | List of exact advisory/component-version decisions described below. |

Release paths and patterns resolve relative to the project root, including
sibling paths. `--release` is an explicit scan override; keep the profile's
saved path right for later runs. Unknown product versions need a real version
before evidence can be current. See [inventory](inventory.md).
Windows releases on another drive are kept as absolute paths that work only
on that machine and may expose personal directory names when reports are shared.

## Manual components

Each component supports `name`, `version`, `ecosystem`, `purl`, `path`, `shipped`
and `note`. Use `npm` or `composer` for supported vulnerability lookups.
Omit `shipped` to keep detected behavior; `true` and `false` are explicit
decisions, and `shipped: null` explicitly makes that occurrence unknown.
These four states and maker comments survive init and unrelated triage saves.
Corrections apply before grouping: an occurrence still shipped wins over unknown
and excluded occurrences; unknown wins when no occurrence remains shipped. Known versions and purls
must come from evidence.

To add an unrecognized library, omit `path`. That field only matches an
already detected occurrence. Record the file location and shipping evidence
in `note`. This example leaves the version unknown until you verify it:

```yaml
components:
  - name: widget
    version: null
    ecosystem: npm
    purl: pkg:npm/widget
    shipped: true
    note: "assets/js/widget.min.js is present in the shipped ZIP; version not yet verified"
```

To correct an already detected occurrence, use its exact path from
`cra/reports/inventory.json`. For example, after verifying the shipped banner:

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

Manual entries can add or correct detected evidence; they do not make unsupported
formats covered or prove the absence of other bundles.

## Saved triage

Prefer [the triage command](vulnerabilities.md#decide-what-a-finding-means-for-this-product).
Each record has `advisory`, `component` (exact purl including version), `status`,
`justification`, `reason`, `decided_on`. Status is `affected`, `not_affected`,
`fixed` or `under_investigation`. All need a reason and decision date;
`not_affected` also needs a supported OpenVEX justification. See
[the generated reference](reference/fendkit_triage.md) for its values.

Profile updates by triage preserve YAML comments. Scan and docs do not save
new answers. Existing maker documents also remain untouched; review changed
facts yourself using [the documents guide](documents.md).
