package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBannerSamples(t *testing.T) {
	files, e := filepath.Glob("../../testdata/banners/*.js")
	if e != nil {
		t.Fatal(e)
	}
	if len(files) != 28 {
		t.Fatalf("want 28 samples, got %d", len(files))
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			b, e := os.ReadFile(file)
			if e != nil {
				t.Fatal(e)
			}
			fixture := strings.TrimSuffix(filepath.Base(file), ".js")
			pair := strings.SplitN(fixture, "@", 2)
			name, version := pair[0], pair[1]
			eco := "npm"
			if name == "selectwoo" {
				name = "woocommerce/selectwoo"
				eco = "github"
			}
			if name == "popper.js" || name == "slick-carousel" {
				version = ""
			}
			cs := BundledJS(b, "assets/vendor.js")
			if len(cs) != 1 {
				t.Fatalf("want one component, got %+v", cs)
			}
			c := cs[0]
			got := ""
			if c.Version != nil {
				got = *c.Version
			}
			if c.Name != name || got != version || c.PURL != PURL(eco, name, version) || c.Evidence[0].Banner == "" {
				t.Fatalf("want %s %s, got %+v (%s)", name, version, c, got)
			}
			if eco == "github" && c.LookupVersion != nil {
				t.Fatal("fork must not be looked up")
			}
		})
	}
}

func TestBannerVariants(t *testing.T) {
	for _, tc := range []struct {
		input, name, version string
		modified             bool
	}{
		{"/* Select2\nCopyright 2012 Igor Vaynberg\nVersion: 3.5.4-tribe */", "select2", "3.5.4-tribe", true},
		{"/*! SelectWoo 1.0.1 */\nwindow.selectWoo = function() {};", "woocommerce/selectwoo", "1.0.1", false},
		{"/*! DataTables 1.13.8 */\nfoo.version=\"2.0.1\";", "datatables.net", "1.13.8", false},
		{"/*! @popperjs/core v2.11.8 */", "@popperjs/core", "2.11.8", false},
		{"/*! Select2 4.1.0-rc.0 */", "select2", "4.1.0-rc.0", false},
	} {
		cs := BundledJS([]byte(tc.input), "library.js")
		if len(cs) != 1 {
			t.Fatalf("%s: %+v", tc.input, cs)
		}
		c := cs[0]
		if c.Name != tc.name || c.Version == nil || *c.Version != tc.version || c.Modified != tc.modified {
			t.Fatalf("%s: %+v", tc.input, c)
		}
		if c.Modified && (c.LookupVersion == nil || *c.LookupVersion != "3.5.4") {
			t.Fatal("missing base version")
		}
	}
	for _, input := range []string{"const jquery = require('jquery');", "function select2() { return 'hello'; }", "console.log('a normal app');", "const VERSION = '4.17.15';"} {
		if cs := BundledJS([]byte(input), "jquery-1.0.0.js"); len(cs) > 0 {
			t.Fatalf("false match: %+v", cs)
		}
	}
}

func TestPluginCodeDoesNotIdentifyLibraries(t *testing.T) {
	for _, input := range []string{
		`/* Booking editor */
   const plugin = { version: '1.4.0', clean(html) {return DOMPurify.sanitize(html);} };
   document.body.innerHTML = plugin.clean(location.hash);`,
		`/* Calendar controller */
   function Calendar() {this.version = "3.1.0";this.moment = window.moment;}
   Calendar.prototype.format = function(d) { return this.moment(d).format(); };`,
		`/* Start the Slick slider after images load. */
   const plugin = {version: "2.0.0"};
   jQuery('.slides').slick({autoplay:true});`,
		`/* Confirmation form using sweetalert2 */
   const plugin = { version: "4.2.0" };
   window.Sweetalert2.fire({title: 'Delete booking?'});`,
	} {
		for _, padding := range []string{"", strings.Repeat(" ", 5000)} {
			if cs := BundledJS([]byte(padding+input), "assets/booking.js"); len(cs) != 0 {
				t.Fatalf("application code produced library evidence: %+v", cs)
			}
		}
	}
}

func TestMomentBannerEvidence(t *testing.T) {
	b, e := os.ReadFile("../../testdata/wp-plugin/acme-booking/assets/js/vendor/moment.min.js")
	if e != nil {
		t.Fatal(e)
	}
	cs := BundledJS(b, "moment.min.js")
	if len(cs) != 1 || cs[0].Version == nil || *cs[0].Version != "2.24.0" || cs[0].Source.Banner != "/*! moment.js" {
		t.Fatalf("missing banner evidence: %+v", cs)
	}
}
