# Library banner samples

Real files from cdnjs for the bundled-library detection tests, downloaded on
2026-10-20. Most files are cut to their first 4 KB (the banner comment and
some code). Six files are complete because their minified version has no
version in the banner, so the version has to be found further inside the
file: moment@2.24.0, popper.js@1.16.0, slick-carousel@1.8.1,
datatables.net@1.10.20, dompurify@2.0.8, sweetalert2@9.10.0.

File names are `<npm package>@<version>.js`; the test expects detection of
exactly that package and version. All files keep their original license
headers. Isotope is GPLv3 for open source use and is kept as a 4 KB banner
sample only.
