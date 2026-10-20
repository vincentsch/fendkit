package inventory

import (
	"regexp"
	"strings"

	"github.com/vincentsch/conformline/internal/detect"
)

const maxJS = 2 << 20

// Banner signatures identify libraries independently of the file name.
var bannerRules = []struct{ name, signature, version string }{
	{"jquery", `(?i)jQuery v[0-9]`, `(?i)jQuery v([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"jquery-ui", `(?i)jQuery UI[^\r\n0-9]*v?[0-9]+\.[0-9]+\.[0-9]+`, `(?i)jQuery UI[^\r\n0-9]*([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"jquery-migrate", `(?i)jQuery Migrate`, `(?i)jQuery Migrate v?([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"jquery-validation", `(?i)jQuery Validation Plugin`, `(?i)jQuery Validation Plugin[^\r\n0-9]*([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"bootstrap", `(?mi)^[\s/*!]*Bootstrap v[0-9]`, `(?i)Bootstrap v([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"@popperjs/core", `(?i)@popperjs/core`, `(?i)@popperjs/core[^\r\n0-9]*([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"popper.js", `(?i)Popper\.js|Copyright \(C\) Federico Zivolo`, `(?i)Popper\.js v?([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"select2", `(?i)Select2\s+[0-9]|Copyright 2012 Igor Vaynberg`, `(?i)(?:Select2\s+|Version:\s*)v?([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"selectwoo", `(?i)SelectWoo\s+[0-9]`, `(?i)SelectWoo\s+v?([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"moment", `(?mi)^[\t /*!]*moment\.js|:\s*[\w$]+\.moment\s*=\s*[\w$]+\(\)`, `(?i)(?:version\s*[:=]\s*["']?|moment\.js\s*[-:]?\s*v?)([0-9]+\.[0-9]+\.[0-9]+(?:-[\w.-]+)?)`},
	{"lodash", `(?i)Lodash lodash\.com|lodash v`, `(?:VERSION\s*=\s*["']|(?i:lodash v))([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"underscore", `(?i)Underscore\.js`, `(?i)Underscore\.js\s+([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"handlebars", `(?i)handlebars v`, `(?i)handlebars v([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"vue", `(?i)Vue\.js v`, `(?i)Vue\.js v([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"react", `(?i)@license React v`, `(?i)@license React v([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"chart.js", `(?i)Chart\.js v`, `(?i)Chart\.js v([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"swiper", `(?i)Swiper\s+[0-9]`, `(?i)Swiper\s+([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"slick-carousel", `(?mi)^[\t /*!]*Slick\s+v?[0-9]|window\.Slick\s*\|\|\s*\{\}`, `(?i)slick\s*[-:]?\s*v?([0-9]+\.[0-9]+\.[0-9]+)`},
	{"magnific-popup", `(?i)Magnific Popup`, `(?i)Magnific Popup[^\r\n0-9]*([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"datatables.net", `(?i)DataTables\s+[0-9]`, `(?i)DataTables\s+([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"dompurify", `(?mi)^[\t /*!]*DOMPurify\s+v?[0-9]|:\s*[\w$]+\.DOMPurify\s*=\s*[\w$]+\(\)`, `version\s*[:=]\s*["']([0-9]+\.[0-9]+\.[0-9]+(?:-[\w.-]+)?)`},
	{"axios", `(?i)axios v`, `(?i)axios v([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"sweetalert2", `(?mi)^[\t /*!]*SweetAlert2\s+v?[0-9]|:\s*(?:\([^\r\n)]{1,80}\)|[\w$]+)\.Sweetalert2\s*=\s*[\w$]+\(\)`, `version\s*[:=]\s*["']([0-9]+\.[0-9]+\.[0-9]+(?:-[\w.-]+)?)`},
	{"flatpickr", `(?i)flatpickr v`, `(?i)flatpickr v([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"fullcalendar", `(?i)FullCalendar v`, `(?i)FullCalendar v([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"clipboard", `(?i)clipboard\.js v`, `(?i)clipboard\.js v([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"isotope-layout", `(?i)Isotope PACKAGED`, `(?i)Isotope PACKAGED v([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
	{"lightbox2", `(?i)Lightbox v`, `(?i)Lightbox v([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)`},
}

type compiledBanner struct {
	name               string
	signature, version *regexp.Regexp
}

var signatures = func() []compiledBanner {
	out := []compiledBanner{}
	for _, r := range bannerRules {
		out = append(out, compiledBanner{r.name, regexp.MustCompile(r.signature), regexp.MustCompile(r.version)})
	}
	return out
}()
var releaseVersion = regexp.MustCompile(`^v?([0-9]+\.[0-9]+\.[0-9]+)(.*)$`)
var lodashSignature = regexp.MustCompile(`(?i)Lodash`)
var prerelease = regexp.MustCompile(`^-(?:alpha|beta|rc|pre|preview|dev|next|canary)(?:[.0-9-].*)?$`)

func BundledJS(b []byte, file string) []Component {
	if len(b) > maxJS {
		b = b[:maxJS]
	}
	head := b
	if len(head) > 4096 {
		head = head[:4096]
	}
	out := []Component{}
	for _, r := range signatures {
		sample := head
		loc := r.signature.FindIndex(sample)
		if loc == nil {
			continue
		}
		if r.name == "underscore" && lodashSignature.Match(head) {
			continue
		}
		name, eco := r.name, "npm"
		if name == "select2" && strings.Contains(string(b), "selectWoo") {
			name = "selectwoo"
		}
		if name == "selectwoo" {
			eco = "github"
			name = "woocommerce/selectwoo"
		}
		if name == "react" && strings.Contains(string(head), "react-dom.") {
			name = "react-dom"
		}
		version := ""
		if m := r.version.FindSubmatch(b); m != nil {
			version = string(m[1])
		}
		start, end := loc[0], loc[1]
		for start > 0 && sample[start-1] != '\n' && loc[0]-start < 150 {
			start--
		}
		for end < len(sample) && sample[end] != '\n' && end-start < 300 {
			end++
		}
		ev := Evidence{File: file, Method: "bundled JavaScript", Path: file, Banner: string(sample[start:end])}
		c := component(eco, name, version, false, ev)
		c.Shipped = boolPtr(true)
		c.Evidence[0].Shipped = c.Shipped
		c.Source.Shipped = c.Shipped
		if eco == "github" {
			c.LookupVersion = nil
			c.Note = "SelectWoo is a fork; advisory lookups are not available"
		}
		if m := releaseVersion.FindStringSubmatch(version); m != nil && m[2] != "" && !strings.HasPrefix(m[2], "+") && !prerelease.MatchString(m[2]) {
			c.Modified = true
			c.LookupVersion = detect.String(m[1])
			c.Note = "Based on " + m[1] + "; this is a modified copy, check whether the fix is in"
		}
		out = append(out, c)
	}
	return out
}

func LibraryDisplayName(name string) string {
	names := map[string]string{
		"jquery": "jQuery", "jquery-ui": "jQuery UI", "jquery-migrate": "jQuery Migrate", "jquery-validation": "jQuery Validation",
		"bootstrap": "Bootstrap", "popper.js": "Popper", "@popperjs/core": "Popper", "select2": "Select2", "woocommerce/selectwoo": "SelectWoo",
		"moment": "moment.js", "lodash": "Lodash", "underscore": "Underscore", "handlebars": "Handlebars", "vue": "Vue", "react": "React", "react-dom": "React DOM",
		"chart.js": "Chart.js", "swiper": "Swiper", "slick-carousel": "Slick", "magnific-popup": "Magnific Popup", "datatables.net": "DataTables", "dompurify": "DOMPurify",
		"axios": "axios", "sweetalert2": "SweetAlert2", "flatpickr": "flatpickr", "fullcalendar": "FullCalendar", "clipboard": "clipboard.js", "isotope-layout": "Isotope", "lightbox2": "Lightbox2",
	}
	if display, ok := names[name]; ok {
		return display
	}
	return name
}
