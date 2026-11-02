package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
	// Unknown keys are rejected so a typo (defaultAcion, effect) is
	// reported instead of being ignored.
	var raw rawPolicyDoc
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	p := &Policy{
		ID:             raw.Policy.ID,
		Name:           raw.Policy.Name,
		DefaultAction:  raw.Policy.DefaultAction,
		WritableDirs:   raw.Policy.WritableDirs,
		SensitivePaths: raw.Policy.SensitivePaths,
		Actions:        map[string]*Action{},
	}
	if len(p.WritableDirs) == 0 {
		p.WritableDirs = raw.WritableDirs
	}
	if len(p.SensitivePaths) == 0 {
		p.SensitivePaths = raw.SensitivePaths
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
		if a == nil {
			// `name:` with no body: report it instead of dereferencing nil.
			return nil, fmt.Errorf("policy invalid: action %q has no definition (needs effectiveAction)", name)
		}
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
		ID             string   `yaml:"id"`
		Name           string   `yaml:"name"`
		DefaultAction  string   `yaml:"defaultAction"`
		WritableDirs   []string `yaml:"writableDirs"`
		SensitivePaths []string `yaml:"sensitivePaths"`
	} `yaml:"policy"`
	ID             string             `yaml:"id"`
	Name           string             `yaml:"name"`
	DefaultAction  string             `yaml:"defaultAction"`
	WritableDirs   []string           `yaml:"writableDirs"`
	SensitivePaths []string           `yaml:"sensitivePaths"`
	Actions        map[string]*Action `yaml:"actions"`
	Rules          []Rule             `yaml:"rules"`
}
