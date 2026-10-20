# Library banner samples

Real files from cdnjs (`https://cdnjs.cloudflare.com/ajax/libs/<library>/<version>/`)
for the bundled-library detection tests, downloaded on 2026-10-20. Most files
are cut to their first 4 KB (the banner comment and some code). Six files are
complete because the version sits further inside the file or the file has
none: moment@2.24.0, popper.js@1.16.0, slick-carousel@1.8.1,
datatables.net@1.10.20, dompurify@2.0.8, sweetalert2@9.10.0.

File names are `<npm package>@<version>.js`. The test expects detection of
exactly that package and version, except for popper.js@1.16.0 and
slick-carousel@1.8.1: their minified files contain no version string at all,
so the expected result is the package name with "version unknown". DataTables
has `DataTables 1.10.20` in its banner after the license text (byte 446).
moment, dompurify and sweetalert2 carry the version inside the code
(`c.version="2.24.0"`, `t.version="2.0.8"`, `Je.version="9.10.0"`).

## Licenses

The samples are excerpts of third-party libraries. They keep their original
license headers and stay under their own licenses, not under this
repository's MIT license: DOMPurify is MPL-2.0 or Apache-2.0; every other
library here is MIT, except Isotope. Isotope is GPLv3 for open source use, so
`isotope-layout@3.0.6.js` contains only its banner comment and no code.
