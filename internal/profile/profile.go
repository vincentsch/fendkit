package profile

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Product struct {
	Name         *string  `yaml:"name"`
	Type         *string  `yaml:"type"`
	Version      *string  `yaml:"version"`
	Description  *string  `yaml:"description"`
	Release      *string  `yaml:"release"`
	Distribution []string `yaml:"distribution"`
}
type Manufacturer struct {
	Name    *string `yaml:"name"`
	Address *string `yaml:"address"`
	Website *string `yaml:"website"`
}
type Answers struct {
	Sold          *bool `yaml:"sold"`
	PaidEdition   *bool `yaml:"paid_edition"`
	PaidSupport   *bool `yaml:"paid_support"`
	DonationsOnly *bool `yaml:"donations_only"`
	HostedOnly    *bool `yaml:"hosted_only"`
}
type Role struct {
	Answer    string  `yaml:"answer"`
	Answers   Answers `yaml:"answers"`
	DecidedBy *string `yaml:"decided_by"`
	DecidedOn *string `yaml:"decided_on"`
}
type Classification struct {
	Answer     string   `yaml:"answer"`
	Categories []string `yaml:"categories"`
	DecidedBy  *string  `yaml:"decided_by"`
	DecidedOn  *string  `yaml:"decided_on"`
	Note       *string  `yaml:"note"`
}
type Contact struct {
	Email     *string `yaml:"email"`
	URL       *string `yaml:"url"`
	PolicyURL *string `yaml:"policy_url"`
}
type Support struct {
	End      *string `yaml:"end"`
	Versions *string `yaml:"versions"`
	Updates  *string `yaml:"updates"`
}
type Component struct {
	Name      *string `yaml:"name"`
	Version   *string `yaml:"version"`
	Ecosystem *string `yaml:"ecosystem"`
	PURL      *string `yaml:"purl"`
	Path      *string `yaml:"path"`
	Shipped   *bool   `yaml:"shipped"`
	Note      *string `yaml:"note"`
}
type Triage struct {
	Advisory      *string `yaml:"advisory"`
	Component     *string `yaml:"component"`
	Status        *string `yaml:"status"`
	Justification *string `yaml:"justification"`
	Reason        *string `yaml:"reason"`
	DecidedOn     *string `yaml:"decided_on"`
}
type Profile struct {
	Version         int            `yaml:"version"`
	Product         Product        `yaml:"product"`
	Manufacturer    Manufacturer   `yaml:"manufacturer"`
	Role            Role           `yaml:"role"`
	Classification  Classification `yaml:"classification"`
	SecurityContact Contact        `yaml:"security_contact"`
	Support         Support        `yaml:"support"`
	Components      []Component    `yaml:"components"`
	Triage          []Triage       `yaml:"triage"`
	node            yaml.Node
}

func Load(path string) (*Profile, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	return Parse(b)
}
func Parse(b []byte) (*Profile, error) {
	p := &Profile{}
	d := yaml.NewDecoder(bytes.NewReader(b))
	if e := d.Decode(&p.node); e != nil {
		return nil, fmt.Errorf("cra.yml: invalid YAML; fix the YAML syntax")
	}
	var extra yaml.Node
	if e := d.Decode(&extra); e != io.EOF {
		return nil, fmt.Errorf("cra.yml: use one YAML document")
	}
	if len(p.node.Content) != 1 || p.node.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("cra.yml: expected a mapping; start with version: 1")
	}
	if e := validateTypes(p.node.Content[0], reflect.TypeOf(*p), ""); e != nil {
		return nil, e
	}
	if e := validate(p.node.Content[0], ""); e != nil {
		return nil, e
	}
	if e := p.node.Decode(p); e != nil {
		return nil, fmt.Errorf("cra.yml: invalid field type; use the documented profile field types")
	}
	if p.Version != 1 {
		return nil, fmt.Errorf("version: unsupported schema; set version: 1")
	}
	if p.Role.Answer == "" {
		p.Role.Answer = "unknown"
	}
	if p.Classification.Answer == "" {
		p.Classification.Answer = "unknown"
	}
	return p, nil
}

var enums = map[string]string{
	"product.type":           "wordpress-plugin wordpress-theme composer-package npm-package application other",
	"role.answer":            "manufacturer open-source-steward not-in-scope unknown",
	"classification.answer":  "default important-class-i important-class-ii critical unknown",
	"triage[].status":        "affected not_affected fixed under_investigation",
	"triage[].justification": "component_not_present vulnerable_code_not_present vulnerable_code_not_in_execute_path vulnerable_code_cannot_be_controlled_by_adversary inline_mitigations_already_exist",
}

func validate(n *yaml.Node, path string) error {
	if n.Kind == yaml.AliasNode {
		return validate(n.Alias, path)
	}
	if n.Tag == "!!null" {
		return nil
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			next := k.Value
			if path != "" {
				next = path + "." + next
			}
			if seen[k.Value] {
				return fmt.Errorf("%s: duplicate field; keep one value", next)
			}
			seen[k.Value] = true
			if e := validate(v, next); e != nil {
				return e
			}
		}
		return nil
	}
	if n.Kind == yaml.SequenceNode {
		for i, v := range n.Content {
			if e := validate(v, fmt.Sprintf("%s[%d]", path, i)); e != nil {
				return e
			}
		}
		return nil
	}
	normalized := path
	for {
		a := strings.Index(normalized, "[")
		if a < 0 {
			break
		}
		z := strings.Index(normalized[a:], "]")
		if z < 0 {
			break
		}
		normalized = normalized[:a] + "{}" + normalized[a+z+1:]
	}
	normalized = strings.ReplaceAll(normalized, "{}", "[]")
	if choices, ok := enums[normalized]; ok && !slices.Contains(strings.Fields(choices), n.Value) {
		return fmt.Errorf("%s: invalid value; choose %s or null", path, choices)
	}
	if strings.HasSuffix(path, ".decided_on") || path == "support.end" {
		if _, e := time.Parse("2006-01-02", n.Value); e != nil {
			return fmt.Errorf("%s: invalid date; use YYYY-MM-DD or null", path)
		}
	}
	if strings.HasPrefix(path, "role.answers.") || strings.HasSuffix(normalized, "[].shipped") {
		if n.Tag != "!!bool" {
			return fmt.Errorf("%s: invalid answer; use true, false or null", path)
		}
	}
	return nil
}

func (p *Profile) Save(path string) error {
	if p.Role.Answer == "" {
		p.Role.Answer = "unknown"
	}
	if p.Classification.Answer == "" {
		p.Classification.Answer = "unknown"
	}
	var fresh yaml.Node
	if e := fresh.Encode(p); e != nil {
		return e
	}
	if e := validateTypes(&fresh, reflect.TypeOf(*p), ""); e != nil {
		return e
	}
	if e := validate(&fresh, ""); e != nil {
		return e
	}
	if p.Version != 1 {
		return fmt.Errorf("version: set version: 1")
	}
	if len(p.node.Content) == 0 {
		p.node = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{&fresh}}
	} else {
		merge(p.node.Content[0], &fresh)
	}
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if e := enc.Encode(&p.node); e != nil {
		return e
	}
	if e := enc.Close(); e != nil {
		return e
	}
	return os.WriteFile(path, b.Bytes(), 0644)
}
func merge(old, new *yaml.Node) {
	if old.Kind == yaml.MappingNode && new.Kind == yaml.MappingNode {
		for i := 0; i < len(new.Content); i += 2 {
			found := false
			for j := 0; j < len(old.Content); j += 2 {
				if old.Content[j].Value == new.Content[i].Value {
					merge(old.Content[j+1], new.Content[i+1])
					key, value := old.Content[j], old.Content[j+1]
					// Block collections print their inline comment beside the mapping key.
					if (value.Kind == yaml.SequenceNode || value.Kind == yaml.MappingNode) && value.Style&yaml.FlowStyle == 0 && value.LineComment != "" {
						if key.LineComment != "" {
							key.LineComment += "\n"
						}
						key.LineComment += value.LineComment
						value.LineComment = ""
					}
					found = true
					break
				}
			}
			if !found {
				old.Content = append(old.Content, new.Content[i], new.Content[i+1])
			}
		}
		return
	}
	if old.Kind == yaml.SequenceNode && new.Kind == yaml.SequenceNode {
		for i := range new.Content {
			if i < len(old.Content) {
				merge(old.Content[i], new.Content[i])
				new.Content[i] = old.Content[i]
			}
		}
	}
	head, line, foot := old.HeadComment, old.LineComment, old.FootComment
	*old = *new
	old.HeadComment, old.LineComment, old.FootComment = head, line, foot
}

func validateTypes(n *yaml.Node, t reflect.Type, path string) error {
	if n.Kind == yaml.AliasNode {
		return validateTypes(n.Alias, t, path)
	}
	if n.Tag == "!!null" {
		return nil
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	bad := func(want string) error {
		return fmt.Errorf("%s: expected %s; use the documented field type or null", path, want)
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			return bad("a mapping")
		}
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i].Value
			next := key
			if path != "" {
				next = path + "." + key
			}
			found := false
			for j := 0; j < t.NumField(); j++ {
				f := t.Field(j)
				if f.PkgPath != "" {
					continue
				}
				if f.Tag.Get("yaml") == key {
					found = true
					if e := validateTypes(n.Content[i+1], f.Type, next); e != nil {
						return e
					}
					break
				}
			}
			if !found {
				return fmt.Errorf("%s: unknown field; remove it or use a documented profile field", next)
			}
		}
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode {
			return bad("a list")
		}
		for i, v := range n.Content {
			if e := validateTypes(v, t.Elem(), fmt.Sprintf("%s[%d]", path, i)); e != nil {
				return e
			}
		}
	case reflect.Bool:
		if n.Tag != "!!bool" {
			return bad("true or false")
		}
	case reflect.Int:
		if n.Tag != "!!int" {
			return bad("an integer")
		}
	case reflect.String:
		if n.Kind != yaml.ScalarNode || (n.Tag != "!!str" && n.Tag != "!!timestamp" && n.Tag != "!!int" && n.Tag != "!!float") {
			return bad("text")
		}
	}
	return nil
}
