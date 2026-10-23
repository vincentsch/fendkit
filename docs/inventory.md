# Know what you ship

Fendkit reads your source project and, when available, the ZIP or folder
you release. It does not run a package manager or execute your product.
The [README](../README.md#start-on-your-plugin) shows the first run.

## Detection and package evidence

WordPress plugin headers, theme style headers and readme.txt identify products.
Composer and npm manifests supply package facts. When versions conflict,
review the detected header, Stable tag and `product.version`; do not invent
a version to silence a warning.

Composer inventory reads composer.lock and installed.json, including v1/v2
installed formats. npm inventory reads package-lock.json v2/v3 and
npm-shrinkwrap.json. pnpm and Yarn lockfiles are named as unsupported; their
dependencies are not scanned. Manifests without resolved installed versions
leave coverage gaps rather than guessed versions.

## The release boundary

```bash
fendkit scan --release ../dist/plugin.zip
```

Paths are relative to the project root (`--dir`), including sibling paths.
Windows releases on another drive are kept as absolute paths that work only
on that machine and may expose personal directory names when reports are shared.
A release folder works too. A ZIP may be flat or have one enclosing folder.
If the release is missing or unreadable, the scan stops with an error.
If its product version differs from source, the error shows both versions.
Build the intended release or correct the source facts first.
Detected WordPress plugin/theme names and Composer/npm manifest package names
are also compared with corresponding release metadata. Conflicting identities
stop the scan before reports are replaced. A profile display-name override
does not change the detected identity. An enclosing folder name or a generated
package URL cannot establish identity. If Fendkit cannot compare the metadata,
it shows **Release identity unverified**. Confirm that you supplied the right release.

**Shipped** means evidence places the component in the distributed product.
**Development** means it is outside that boundary or only a development tool.
**Unknown** means the tool cannot settle whether it ships. Unknown components
stay visible for review and possible vulnerability findings.

Without a release, Composer runtime and recognised bundled JS count as shipped;
Composer development dependencies do not. npm dependencies can remain unknown:
a build dependency might be bundled or stay outside the release. A release
lets the scanner distinguish those cases using files and package evidence.
For Composer, Fendkit checks known install paths before treating a package as
absent. Files without installed version metadata appear separately as possibly
shipped with an unknown version. The report shows their path and a coverage gap.
The lockfile entry stays visible, but its version cannot establish what ships.
Fendkit only looks up advisories for known versions. It uses supported installed
metadata when available, including nested vendor trees. Absent packages stay excluded.
Coverage gaps need your review even when all lookups succeed and scan exits 0.

In the JSON report, that unknown release copy has null `version` and
`lookup_version` fields. Its package URL (PURL) has no version and its SBOM scope
is `required`.

## Bundled libraries and gaps

The scanner recognises selected JavaScript libraries from banners, including
moment.js, Select2/SelectWoo and jQuery Validation. It searches supported files,
not arbitrary minified code; JavaScript reads stop at 2 MiB per file.
A missing version stays unknown. A modified copy needs review because upstream
advisories cannot cover local changes. Renamed or stripped bundles may go
unrecognised. Review the files you ship yourself as well.

Add known manual components or corrections through [cra.yml](cra-yml.md#manual-components).
Do not assign a version without evidence. Go, Python, firmware and container
formats are outside v0.1 dependency coverage. The tool does not scan your own
code for vulnerabilities.

Scan writes the inventory to `cra/reports/inventory.json` and the software bill
of materials (SBOM) to `cra/reports/sbom.cdx.json`. It also writes
[vulnerability reports](vulnerabilities.md). CycloneDX 1.6 is the SBOM format;
it records discovered components and shipping evidence, not proof of complete
coverage. An offline scan still writes inventory but exits 11 because lookups
are missing. Run `fendkit check` after scan to see [status](status-items.md).
