package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadFromFile reads a YAML policy file.
func LoadFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Load(data)
}

// Load decodes YAML/JSON-compatible bytes into a Policy.
func Load(data []byte) (*Policy, error) {
	var raw rawPolicyDoc
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	p := &Policy{
		ID:            raw.Policy.ID,
		Name:          raw.Policy.Name,
		DefaultAction: raw.Policy.DefaultAction,
		Actions:       map[string]*Action{},
	}
	if p.ID == "" {
		// Allow flat layout where actions/rules sit at top level.
		p.ID = raw.ID
		if p.Name == "" {
			p.Name = raw.Name
		}
		if p.DefaultAction == "" {
			p.DefaultAction = raw.DefaultAction
		}
	}
	for name, a := range raw.Actions {
		ac := *a
		ac.Name = name
		if ac.Severity == 0 {
			ac.Severity = severityFor(ac.EffectiveAction)
		}
		p.Actions[name] = &ac
	}
	for _, r := range raw.Rules {
		rr := r
		p.Rules = append(p.Rules, &rr)
	}
	if errs := p.Validate(); len(errs) > 0 {
		return p, fmt.Errorf("policy invalid: %v", errs)
	}
	p.EnsureSorted()
	return p, nil
}

type rawPolicyDoc struct {
	Policy struct {
		ID            string `yaml:"id"`
		Name          string `yaml:"name"`
		DefaultAction string `yaml:"defaultAction"`
	} `yaml:"policy"`
	ID            string             `yaml:"id"`
	Name          string             `yaml:"name"`
	DefaultAction string             `yaml:"defaultAction"`
	Actions       map[string]*Action `yaml:"actions"`
	Rules         []Rule             `yaml:"rules"`
}
