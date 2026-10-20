package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCategorySelections(t *testing.T) {
	entries := Categories()
	if len(entries) != 26 {
		t.Fatal(len(entries))
	}
	for i, c := range entries {
		want := fmt.Sprintf("i-%d", i+1)
		if i >= 19 {
			want = fmt.Sprintf("ii-%d", i-18)
		}
		if i >= 23 {
			want = fmt.Sprintf("iv-%d", i-22)
		}
		if c.ID != want || c.Name == "" || c.Explanation == "" || len(c.Examples) < 1 || len(c.Examples) > 2 {
			t.Fatalf("entry %d: %+v", i, c)
		}
		ids, _, err := ParseSelection(fmt.Sprint(i + 1))
		if err != nil || len(ids) != 1 || ids[0] != want {
			t.Fatalf("display mapping %d: %v %v", i, ids, err)
		}
	}
	for _, tc := range []struct{ input, want string }{
		{"", "unknown"}, {"unknown", "unknown"}, {"0", "default"}, {"3", "important-class-i"},
		{"3,20", "important-class-ii"}, {"3,20,26", "critical"}, {"24,20,3", "critical"},
	} {
		_, got, err := ParseSelection(tc.input)
		if err != nil || got != tc.want {
			t.Fatalf("%q: %s %v", tc.input, got, err)
		}
	}
	for _, input := range []string{"0,3", "3,0", "27", "-1", "3,", "x"} {
		if _, _, err := ParseSelection(input); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
	if _, err := Parse([]byte("version: 1\nclassification: {categories: [missing]}")); err == nil || !strings.Contains(err.Error(), "classification.categories") {
		t.Fatal(err)
	}
}
func TestExplicitUnknownPresence(t *testing.T) {
	p, err := Parse([]byte("version: 1\nmanufacturer: {name: Example Maker}\nsecurity_contact: {email: null}\nrole: {answer: unknown}\nsupport: null\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"manufacturer.name", "security_contact.email", "role.answer", "support.end"} {
		if !p.HasAnswer(path) {
			t.Fatal(path)
		}
	}
	for _, path := range []string{"manufacturer.address", "role.answers.sold", "classification.categories"} {
		if p.HasAnswer(path) {
			t.Fatal(path)
		}
	}
}

func TestUnknownCategoryRoundTrip(t *testing.T) {
	p, err := Parse([]byte("# Maker comment\nversion: 1\nclassification: {answer: unknown, categories: null}\n"))
	if err != nil {
		t.Fatal(err)
	}
	p.AddGuidance()
	path := filepath.Join(t.TempDir(), "cra.yml")
	if err := p.Save(path); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "# Maker comment") || !strings.Contains(string(b), "categories: null") {
		t.Fatal(string(b))
	}
	again, err := Load(path)
	if err != nil || again.Classification.Categories != nil {
		t.Fatal(again, err)
	}
}
