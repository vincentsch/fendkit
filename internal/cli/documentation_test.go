package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/vincentsch/fendkit/internal/profile"
	"github.com/vincentsch/rungrad/testutil"
)

func TestPublicDocumentation(t *testing.T) {
	root := filepath.Join("..", "..")
	files, err := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, filepath.Join(root, "README.md"), filepath.Join(root, "AGENTS.md"))
	inline := regexp.MustCompile(`!?\[[^\]\n]*\]\(<?([^\s)>]+)>?(?:\s+"[^"]*")?\)`)
	reference := regexp.MustCompile(`(?m)^\s{0,3}\[[^\]]+\]:\s*<?([^\s>]+)>?`)
	attributes := regexp.MustCompile(`(?:href|src|srcset)="([^"]+)"`)
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			// Keep these phrases aligned with the generated-document legal wording checks.
			for _, bad := range []string{"compliant product", "cra compliant", "certified", "guarantee", "ensures compliance", "cra-ready"} {
				if strings.Contains(strings.ToLower(text), bad) {
					t.Errorf("forbidden wording %q", bad)
				}
			}
			for _, pattern := range []*regexp.Regexp{inline, reference, attributes} {
				for _, match := range pattern.FindAllStringSubmatch(text, -1) {
					checkDocumentationLink(t, file, match[1])
				}
			}
		})
	}
	// Validate the published example through the profile reader and the real command tree.
	data, err := os.ReadFile(filepath.Join(root, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, example, ok := strings.Cut(string(data), "```yaml\n")
	if !ok {
		t.Fatal("missing partial answers example")
	}
	example, _, ok = strings.Cut(example, "```")
	if !ok {
		t.Fatal("unclosed partial answers example")
	}
	p, err := profile.Parse([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	if p.Classification.Answer != "unknown" || p.Classification.Categories != nil {
		t.Fatal("example must preserve unknown classification")
	}
	maker := t.TempDir()
	copyTree(t, filepath.Join(root, "testdata/wp-plugin/acme-booking"), maker)
	answers := filepath.Join(t.TempDir(), "answers.yml")
	if err := os.WriteFile(answers, []byte(example), 0600); err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(rootPath(t), "testdata/wp-plugin/dist/acme-booking-2.3.1.zip")
	result := testutil.RunWith(New(), testutil.Options{}, "init", "--dir", maker, "--offline", "--no-prompt", "--answers", answers, "--release", release)
	if result.Exit != 11 {
		t.Fatalf("init: %+v", result)
	}
	saved, err := profile.Load(filepath.Join(maker, "cra.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if saved.Classification.Answer != "unknown" || saved.Classification.Categories != nil {
		t.Fatal("init changed unknown classification")
	}

	wantRelease := expectedReleasePath(t, maker, release)
	wantPattern := strings.Replace(wantRelease, "2.3.1.zip", "{version}.zip", 1)
	if saved.Product.Release == nil || *saved.Product.Release != wantPattern {
		t.Fatalf("saved release: %+v; want %s", saved.Product, wantPattern)
	}
	var inv Report
	if err := json.Unmarshal([]byte(readFile(t, maker, "cra/reports/inventory.json")), &inv); err != nil {
		t.Fatal(err)
	}
	if inv.Release == nil || *inv.Release != wantRelease {
		t.Fatalf("recorded release: %+v; want %s", inv.Release, wantRelease)
	}
	checked := testutil.RunWith(New(), testutil.Options{}, "check", "--dir", maker)
	if checked.Exit != 11 || !strings.Contains(checked.Stdout+checked.Stderr, "Decide classification.answer") {
		t.Fatalf("check: %+v", checked)
	}
}

func rootPath(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func checkDocumentationLink(t *testing.T, source, target string) {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Errorf("invalid link %q: %v", target, err)
		return
	}
	if u.IsAbs() || u.Host != "" {
		return
	}
	path := source
	if u.Path != "" {
		path = filepath.Join(filepath.Dir(source), filepath.FromSlash(u.Path))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Errorf("broken link %q: %v", target, err)
		return
	}
	if u.Fragment == "" {
		return
	}
	if info.IsDir() {
		path = filepath.Join(path, "README.md")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Error(err)
		return
	}
	anchors := documentationAnchors(string(data))
	if !anchors[u.Fragment] {
		t.Errorf("missing heading %q in %s (link %s)", u.Fragment, path, target)
	}
}

func documentationAnchors(text string) map[string]bool {
	anchors := map[string]bool{}
	seen := map[string]int{}
	fenced := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "```") || strings.HasPrefix(line, "~~~") {
			fenced = !fenced
			continue
		}
		if fenced || !strings.HasPrefix(line, "#") {
			continue
		}
		heading := strings.TrimLeft(line, "#")
		if !strings.HasPrefix(heading, " ") {
			continue
		}
		heading = strings.TrimSpace(strings.TrimRight(heading, "#"))
		var b strings.Builder
		for _, r := range strings.ToLower(heading) {
			switch {
			case r == ' ' || r == '-':
				b.WriteRune('-')
			case unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_':
				b.WriteRune(r)
			}
		}
		anchor := b.String()
		n := seen[anchor]
		seen[anchor]++
		if n > 0 {
			anchor += "-" + fmt.Sprint(n)
		}
		anchors[anchor] = true
	}
	return anchors
}

func TestManualAdditionGuide(t *testing.T) {
	text, err := os.ReadFile("../../docs/cra-yml.md")
	if err != nil {
		t.Fatal(err)
	}
	_, example, ok := strings.Cut(string(text), "```yaml\ncomponents:\n")
	if !ok {
		t.Fatal("manual addition example missing")
	}
	example, _, ok = strings.Cut(example, "```")
	if !ok {
		t.Fatal("manual addition example not closed")
	}
	root := t.TempDir()
	put(t, root, "package.json", `{"name":"sample","version":"1.0.0"}`)
	if err := os.MkdirAll(filepath.Join(root, "assets/js"), 0755); err != nil {
		t.Fatal(err)
	}
	put(t, root, "assets/js/widget.min.js", "/* Unrecognized library with no version evidence. */")
	put(t, root, "cra.yml", "version: 1\nrole: {answer: not-in-scope}\ncomponents:\n"+example)
	runCheckCLI(t, nil, root, 11, "scan", "--offline", "--release", ".")
	var result Report
	if err := json.Unmarshal([]byte(readFile(t, root, "cra/reports/inventory.json")), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Components) != 1 {
		t.Fatal(result.Components)
	}
	component := result.Components[0]
	if component.Name != "widget" || component.Version != nil || component.Shipped == nil || !*component.Shipped || component.PURL != "pkg:npm/widget" {
		t.Fatal(component)
	}
}
