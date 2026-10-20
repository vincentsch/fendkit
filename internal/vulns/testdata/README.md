# Advisory fixtures

These responses came from OSV.dev on October 20, 2026, using the example
Acme Booking inventory. `acme-responses.json` keeps the query-to-id mapping
and advisory fields used by reports. Long affected-version lists keep a few
examples; affected ranges remain intact. References keep their first two
entries. These fixtures never use the network during tests.

The three Guzzle files preserve both GHSA ids that alias each other and the
separate fixes for releases 7 and 8. They omit expanded version lists and
unrelated prose. Their ranges exercise update advice on installed 7.4.0.

The KEV fixture is authored test data. It deliberately includes
CVE-2022-31042 to prove matching through aliases. It makes no claim that this
CVE appears in the live CISA catalog.

Advisories: [OSV.dev](https://osv.dev/) and
[GitHub Advisory Database](https://github.com/advisories),
[CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/).

API and range formats follow the [OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/)
and [OSV schema](https://ossf.github.io/osv-schema/).
