# What ships in your release

Fendkit is a free, open-source CLI for software makers preparing Cyber
Resilience Act evidence. It reads your source project and, when you give it
one, the ZIP or folder you release, and it lists the third-party components in
them. It does not run a package manager and does not execute your product.

The [README](../README.md#start-on-your-plugin) shows the first run.

## Detection and package evidence

A WordPress plugin header, a theme's style header or readme.txt identifies
the product. Composer and npm manifests supply the package facts. When the
versions disagree, look at the detected header, the Stable tag and
`product.version`. Do not invent a version to silence the warning.

For Composer, Fendkit reads `composer.lock` and `installed.json` in the v1 and
v2 formats. For npm, it reads `package-lock.json` v2 and v3 and
`npm-shrinkwrap.json`. It notices pnpm and Yarn lockfiles but cannot read
their dependencies. A manifest on its own does not tell Fendkit which versions
are installed. Those versions stay unknown.

## The release boundary

```bash
fendkit scan --release ../dist/plugin.zip
```

Paths count from the project root (`--dir`), even for a sibling directory. A
release on another Windows drive is kept as an absolute path. That path works
only on that machine, and it can show a personal directory name when you
share the reports. A release folder works like a ZIP. The ZIP may be flat or
have one enclosing folder. If the release is missing or unreadable, the scan
stops with an error. If its product version differs from the source, the
error shows both versions. Build the intended release or fix the source facts
first.

Fendkit also compares the detected plugin or theme name and the Composer and
npm package names with the release metadata. When the identities conflict,
the scan stops before it replaces any report. A display-name override in the
profile does not change the detected identity. A folder name or a generated
package URL does not tell Fendkit which product it is. When Fendkit cannot
compare the metadata, it says **Release identity unverified**. Check that you
passed the right release.

**Shipped** means Fendkit found evidence that the component is in your
release. **Development** means it stays outside the release or is only a
development tool. **Unknown** means Fendkit cannot tell. Unknown components
stay visible for review and can still have vulnerability findings.

Without a release, Composer runtime packages and recognised bundled
JavaScript count as shipped, and Composer development dependencies do not.
npm dependencies can stay unknown, because a build dependency may be bundled
or may stay outside the release. With a release, the scanner uses the files
and the package evidence to tell those cases apart. For Composer, Fendkit
checks the known install paths before it treats a package as absent. A file
without installed version metadata appears separately as possibly shipped
with an unknown version. The report shows its path and a coverage gap. The
lockfile entry stays visible, but its version cannot show what ships. Fendkit
only looks up advisories for known versions. It uses installed metadata when
it has it, including nested vendor trees. Absent packages stay excluded.
Coverage gaps need your review even when all lookups succeed and scan exits 0.

In the JSON report, that unknown release copy has null `version` and
`lookup_version` fields. Its package URL (purl) has no version and its SBOM
scope is `required`.

## Bundled libraries and gaps

The scanner recognises a number of JavaScript libraries by their banner
comments, like moment.js or Select2. The full list is in
`internal/inventory/banners.go`. It reads supported files and stops at 2 MiB
per JavaScript file. It does not try to identify arbitrary minified code. A
library without a version stays unknown. A modified copy needs review,
because an upstream advisory cannot cover local changes. A renamed or
stripped bundle can go unrecognised. So you also need to look through the
files you ship.

Add known components or corrections through
[cra.yml](cra-yml.md#manual-components). Do not give a component a version
without evidence. Go and Python dependencies are not covered in v0.1, and
neither are firmware or container images. Fendkit does not scan your own code
for vulnerabilities.

Scan writes the inventory to `cra/reports/inventory.json` and the software
bill of materials (SBOM) to `cra/reports/sbom.cdx.json`, in CycloneDX 1.6
format. It also writes the [vulnerability reports](vulnerabilities.md). The
SBOM records the components Fendkit found and the shipping evidence for each.
It is not proof that nothing was missed. An offline scan still writes the
inventory but exits 11, because the lookups are missing. Run `fendkit check`
after a scan to see the [status](status-items.md).
