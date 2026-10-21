# WordPress plugin fixture

`acme-booking/` is a small example WordPress plugin used by Fendkit's
tests and demo. It has what real plugins have:

- a plugin header in `acme-booking.php` (version 2.3.1) and a `readme.txt`
  with `Stable tag: 2.3.1`;
- Composer runtime dependencies (`guzzlehttp/guzzle 7.4.0` and its
  dependencies, which have published advisories) and a dev dependency
  (`phpunit/phpunit`), locked in `composer.lock`;
- npm build tools only (`webpack`, `lodash 4.17.15` as devDependencies);
- three old JavaScript libraries copied into `assets/js/vendor/` and not
  listed in any manifest: moment.js 2.24.0, Select2 4.0.5 and jQuery
  Validation 1.19.1, recognisable by their banner comments;
- `vendor/composer/installed.json` as Composer writes it.

`dist/acme-booking-2.3.1.zip` is the release ZIP: plugin files, `includes/`,
`assets/` and `vendor/`, without tests, Composer dev packages, npm files or
lock files. So the shipped product contains Guzzle and the three bundled
libraries, but not PHPUnit, webpack or lodash.

The library files contain only the banner and a stub, not the real library
code.
