Contributors working on Conformline itself: read [CONTRIBUTING.md](CONTRIBUTING.md).

# Prepare a maker's product

These steps apply to another product, where the maker wants CRA evidence.
Locate that project's root first. Check immediately whether it has `cra.yml`.
Branch on that fact before inventory or questions. Do not mistake a checkout
of Conformline for the maker's project.

## Get the tool

Use `conformline` already on PATH. Otherwise follow [installation](docs/install.md):
download the release installer, run it and let it verify the SHA-256 checksum.
If no release exists, say that installation is blocked by the missing release.
When Go is available, offer this fallback:

```bash
go install github.com/vincentsch/conformline/cmd/conformline@latest
```

Windows without Bash needs the manual checksummed download in the install guide.
Never silently use an unverified binary. Run `conformline doctor --dir /path/to/product`.
A missing profile is expected on first use; explain connection failures.

## If cra.yml exists

Preserve saved answers, comments and maker documents. Use the saved release
configuration, unless the maker explicitly overrides it. Go directly to:

```bash
conformline scan --dir /path/to/product
conformline docs --dir /path/to/product
conformline check --dir /path/to/product
```

A request such as “Run the release check again” means **all three commands
above, in order**, even when the saved scan is fresh. Running only check does
not refresh vulnerability evidence or the document index and is insufficient.
Run docs and check after a scan exit 0 or 11; stop and explain operational scan
errors instead of presenting an older report as the new result.

Pass `--release` to scan only for an explicit override. Do not run a preliminary
offline inventory, repeat the interview, or call init. An intentionally unknown
answer is a next action, not a reason to demand another interview.
Then give the final explanation below.

## If cra.yml does not exist

1. Run `conformline scan --offline --dir /path/to/product`, adding
   `--release ../dist/product.zip` when the product release is known.
   Show its Found block before asking questions. Exit 11 means incomplete
   evidence, expected offline. Ask about surprising findings. Never invent a
   component version or replace a library automatically.
2. Ask only for decisions detection cannot make. Ask the maker's role and
   scope first: whether the downloadable product is sold, has a paid edition
   or paid support, is donations-only, or is hosted-only. A manufacturer puts
   the product on the market under their name; an open-source steward supports
   open-source development under a different, lighter regime. Explain the
   distinction using [the CRA guide](docs/cra-for-plugin-makers.md).
   Ask manufacturer name, postal address and website; security email and
   contact/policy URLs; support end date, version line and update method.
   Explain that classification concerns the product's core function under
   Annex III/IV, not the libraries it uses. Show the lists from
   [the regulation](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng).
   Preserve unknowns. Ask an unresolved product version or release location
   only when needed. Use detected product facts.
3. Write a temporary partial-profile YAML file **outside the maker repository**,
   using only the maker's answers. Run init with the chosen project and release:

   ```bash
   conformline init --no-prompt --answers /tmp/maker-answers.yml --dir /path/to/product --release ../dist/product.zip
   ```

   Remove that temporary file after init, including after a failure. Check
   each command's exit code separately; do not join the sequence with `&&`,
   since expected codes 10 and 11 would stop the rest.
4. Give the final explanation below. Never mark a document reviewed for the maker.

## Partial answers example

These are demo answers from Acme Booking, never defaults for another maker.
Product facts come from detection; the release location is passed to init.
The actual profile reader and init accept this file:

```yaml
version: 1
manufacturer:
  name: Acme Plugins GmbH
  address: Musterweg 5, 12345 Musterstadt, Germany
  website: https://example.com
role:
  answer: manufacturer
  answers:
    sold: true
    paid_edition: false
    paid_support: false
    donations_only: false
    hosted_only: false
  decided_by: Demo User
classification:
  answer: unknown
  categories: null
  decided_by: Demo User
security_contact:
  email: security@example.com
  url: null
  policy_url: null
support:
  end: "2031-10-31"
  versions: "2.x"
  updates: WordPress automatic updates
```

`classification.categories: null` preserves unknown. An explicit `[]` means
the maker deliberately decided none of the Annex III/IV categories apply.
It must never stand in for unknown. Do not copy the templated demo answers
as a finished file. See [cra.yml](docs/cra-yml.md) for the schema.

## Explain the result

Name `cra/reports/status.html`, `status.md`, `vulnerabilities.md` and
`sbom.cdx.json`, and `cra/README.md` for the document index. Explain the next
actions, unknown decisions and drafts that need the maker's review.
Scan 0 means complete; scan 11 means incomplete. Check 0 means no configured
failure, 10 means a policy failure, and 11 means missing, incomplete or stale
evidence without a higher-priority policy failure. Operational errors need repair. See
[status rules](docs/status-items.md). Incomplete lookups, unsupported components
and scans older than seven days cannot be presented as clean evidence.

Outputs are drafts and give no legal advice. Findings cover third-party
components, not the maker's own code. Zero findings cannot prove the absence
of vulnerabilities. Explain [network requests and attribution](README.md#privacy-and-limits).
Update bundled libraries only if asked.

Never supply the maker's role or category decision. Never sign or final-date
a declaration, mark a maker document reviewed, or file anything with ENISA.
For incidents, record the awareness time the maker gives; never infer it
from a log or the current clock. Preserve edited evidence and unknown answers.
