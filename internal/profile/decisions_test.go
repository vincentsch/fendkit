package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassificationConsistency(t *testing.T) {
	for _, tc := range []struct {
		input   string
		invalid bool
	}{
		{"categories: [ii-1]", false}, {"categories: []", false},
		{"answer: default, categories: [ii-1]", true},
		{"answer: important-class-ii, categories: [ii-1]", false},
		{"answer: default, categories: []", false},
		{"answer: unknown, categories: null", false}, {"answer: unknown", false},
		{"answer: unknown, categories: []", true}, {"answer: unknown, categories: [ii-1]", true},
		{"answer: null, categories: []", true}, {"answer: null, categories: null", false},
		{"answer: important-class-ii", false}, {"answer: critical, categories: null", false},
	} {
		t.Run(tc.input, func(t *testing.T) {
			p, err := Parse([]byte("version: 1\nclassification: {" + tc.input + "}\n"))
			if tc.invalid {
				if err == nil || !strings.Contains(err.Error(), "classification.answer") {
					t.Fatalf("want field conflict, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			had := p.HasAnswer("classification.answer")
			file := filepath.Join(t.TempDir(), "cra.yml")
			if err = p.Save(file); err != nil {
				t.Fatal(err)
			}
			p, err = Load(file)
			if err != nil {
				t.Fatal(err)
			}
			if p.HasAnswer("classification.answer") != had {
				t.Fatal("manufactured explicit answer")
			}
			if p.Classification.Categories != nil {
				p.Classification.Answer = "critical"
				if err = p.Save(file); err == nil {
					t.Fatal("save accepted conflict")
				}
			}
		})
	}
}

func TestShippingFieldRoundTrip(t *testing.T) {
	for _, field := range []string{"", "shipped: null", "shipped: true", "shipped: false"} {
		t.Run(field, func(t *testing.T) {
			p, err := Parse([]byte("version: 1\ncomponents:\n - path: vendor/guzzlehttp/guzzle # maker path\n   " + field + "\n"))
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "cra.yml")
			for i := 0; i < 2; i++ {
				if err = p.Save(file); err != nil {
					t.Fatal(err)
				}
				b, _ := os.ReadFile(file)
				if !strings.Contains(string(b), "# maker path") {
					t.Fatal("lost comment")
				}
				if field == "" && strings.Contains(string(b), "shipped:") {
					t.Fatal("omitted shipped became explicit")
				}
				if field != "" && !strings.Contains(string(b), field) {
					t.Fatalf("lost %s: %s", field, b)
				}
				p, err = Load(file)
				if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestClassificationAnswerPresenceAcrossSections(t *testing.T) {
	for _, tc := range []struct {
		name, section string
		answered      bool
	}{
		{name: "omitted section"},
		{name: "empty section", section: "classification: {}\n"},
		{name: "categories only", section: "classification: {categories: [ii-1]}\n"},
		{name: "null section", section: "classification: null\n", answered: true},
		{name: "explicit unknown", section: "classification: {answer: unknown}\n", answered: true},
		{name: "explicit null", section: "classification: {answer: null}\n", answered: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse([]byte("# Maker partial answers\nversion: 1\n" + tc.section))
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "answers.yml")
			for i := 0; i < 2; i++ {
				if p.HasAnswer("classification.answer") != tc.answered {
					t.Fatal("classification answer presence changed")
				}
				if err = p.Save(file); err != nil {
					t.Fatal(err)
				}
				b, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(b), "# Maker partial answers") {
					t.Fatal("lost maker comment")
				}
				p, err = Load(file)
				if err != nil {
					t.Fatal(err)
				}
				if p.HasAnswer("classification.answer") != tc.answered {
					t.Fatal("classification answer presence changed after save/reload")
				}
			}
		})
	}
}
