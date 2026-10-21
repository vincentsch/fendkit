package profile

import (
	"embed"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed annex.json
var annexData embed.FS

type Category struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Explanation string   `json:"explanation"`
	Examples    []string `json:"examples"`
}

func Categories() []Category {
	b, _ := annexData.ReadFile("annex.json")
	var entries []Category
	if err := json.Unmarshal(b, &entries); err != nil {
		panic(err)
	}
	return entries
}

func Classify(ids []string) (string, error) {
	answer := "default"
	entries := Categories()
	for _, id := range ids {
		found := false
		for _, c := range entries {
			if c.ID == id {
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("classification.categories: unknown category %q; use an id from the Annex III/IV list", id)
		}
		if strings.HasPrefix(id, "iv-") {
			answer = "critical"
		} else if strings.HasPrefix(id, "ii-") && answer != "critical" {
			answer = "important-class-ii"
		} else if strings.HasPrefix(id, "i-") && answer == "default" {
			answer = "important-class-i"
		}
	}
	return answer, nil
}

func ParseSelection(text string) ([]string, string, error) {
	text = strings.TrimSpace(text)
	if text == "" || strings.EqualFold(text, "unknown") {
		return nil, "unknown", nil
	}
	if text == "0" {
		return []string{}, "default", nil
	}
	ids := []string{}
	entries := Categories()
	for _, part := range strings.Split(text, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n < 1 || n > len(entries) {
			return nil, "", fmt.Errorf("Choose numbers 1–26 separated by commas, 0 alone for none, or Enter for unknown")
		}
		if !slices.Contains(ids, entries[n-1].ID) {
			ids = append(ids, entries[n-1].ID)
		}
	}
	answer, err := Classify(ids)
	return ids, answer, err
}

// HasAnswer includes an explicit null at this path or any parent.
func (p *Profile) HasAnswer(path string) bool {
	if len(p.node.Content) == 0 {
		return false
	}
	n := p.node.Content[0]
	for _, part := range strings.Split(path, ".") {
		if n.Tag == "!!null" {
			return true
		}
		found := false
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == part {
				n = n.Content[i+1]
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// AddGuidance adds section comments without replacing the maker's comments.
func (p *Profile) AddGuidance() {
	if len(p.node.Content) == 0 {
		p.node = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	header := "Fendkit preparation record. Unknown facts stay null. Review drafts before use."
	if old := p.node.Content[0].HeadComment; old != "" && !strings.HasPrefix(old, header) {
		header += "\n" + old
	}
	p.node.Content[0].HeadComment = header
}
