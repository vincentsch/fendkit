package profile

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Presence matters for maker decisions: omission keeps detection, null is unknown.
func (c *Component) UnmarshalYAML(n *yaml.Node) error {
	type plain Component
	if err := n.Decode((*plain)(c)); err != nil {
		return err
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == "shipped" {
			c.ShippedSet = true
		}
	}
	return nil
}
func (c Component) MarshalYAML() (any, error) {
	type plain Component
	var n yaml.Node
	if err := n.Encode(plain(c)); err != nil {
		return nil, err
	}
	if !c.ShippedSet && c.Shipped == nil {
		removeField(&n, "shipped")
	}
	return &n, nil
}
func (c *Classification) UnmarshalYAML(n *yaml.Node) error {
	type plain Classification
	if err := n.Decode((*plain)(c)); err != nil {
		return err
	}
	c.answerOmitted = true
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == "answer" {
			c.answerOmitted = false
			c.answerNull = n.Content[i+1].Tag == "!!null"
		}
	}
	return nil
}
func (c Classification) MarshalYAML() (any, error) {
	type plain Classification
	var n yaml.Node
	if err := n.Encode(plain(c)); err != nil {
		return nil, err
	}
	if c.Answer == "unknown" || c.Answer == "" {
		if c.answerOmitted {
			removeField(&n, "answer")
		} else if c.answerNull {
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Value == "answer" {
					n.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}
				}
			}
		}
	}
	return &n, nil
}
func removeField(n *yaml.Node, key string) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			n.Content = append(n.Content[:i], n.Content[i+2:]...)
			return
		}
	}
}
func (p *Profile) validateClassification() error {
	c := p.Classification
	class, err := Classify(c.Categories)
	if err != nil {
		return err
	}
	if c.Categories != nil && (!c.answerOmitted || c.Answer != "unknown" && c.Answer != "") && c.Answer != class {
		return fmt.Errorf("classification.answer: conflicts with classification.categories; use %s for the selected categories, or set categories to null to keep an unknown or answer-only decision", class)
	}
	return nil
}
