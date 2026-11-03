// Package policy implements the rule-chain engine.
//
// A Policy is an ordered list of Rules together with a registry of named
// Actions. Rules come in three modes:
//
//   - "enrich": adds tags / risk score / audit notes; does not decide.
//   - "decide": produces a candidate action; usually terminal.
//   - "audit":  records audit information; never terminal, never decides.
//
// Rules are evaluated against every leaf simple command in the IR tree.
// Each leaf gets its own EvaluationState; the final whole-command
// decision aggregates per-leaf decisions using deny > ask > allow.
package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zhaozhaozz/shell-policy/internal/ir"
	"github.com/zhaozhaozz/shell-policy/internal/paths"
)

// Mode is the rule mode.
type Mode string

const (
	ModeEnrich Mode = "enrich"
	ModeDecide Mode = "decide"
	ModeAudit  Mode = "audit"
)

// EffectiveAction is the user-visible final classification.
type EffectiveAction string

const (
	EffectAllow EffectiveAction = "allow"
	EffectAsk   EffectiveAction = "ask"
	EffectDeny  EffectiveAction = "deny"
)

// Action is a named decision outcome with a severity.
type Action struct {
	Name            string          `json:"name" yaml:"name"`
	EffectiveAction EffectiveAction `json:"effectiveAction" yaml:"effectiveAction"`
	Severity        int             `json:"severity" yaml:"severity"`
	UserVisible     string          `json:"userVisible,omitempty" yaml:"userVisible,omitempty"`
	Tags            []string        `json:"tags,omitempty" yaml:"tags,omitempty"`
	// Category marks a switchable category (ask_network, ...). Its effect
	// applies per operation: when it allows, its rules allow the operations
	// they match without hiding them from other rules, so another category's
	// ask or deny on the same operation still applies and the default action
	// does not. A plain allow action instead clears the operations it
	// matches, so that later fallback rules skip them.
	Category bool `json:"category,omitempty" yaml:"category,omitempty"`
	// Relaxes lists boolean context fields this category is about, e.g.
	// context.privilegeEscalated. When the category allows, its rules that
	// test them are skipped and allow rules read them as false: being under
	// sudo is no longer a reason to ask, and the command is judged on its own.
	Relaxes []string `json:"relaxes,omitempty" yaml:"relaxes,omitempty"`
}

// permits reports whether the action is a category that currently allows.
func (a *Action) permits() bool { return a.Category && a.EffectiveAction == EffectAllow }

// Effects describes the side-effects of a matching rule.
type Effects struct {
	AddTags      []string `json:"addTags,omitempty" yaml:"addTags,omitempty"`
	AddRisk      int      `json:"addRisk,omitempty" yaml:"addRisk,omitempty"`
	AddAuditNote string   `json:"addAuditNote,omitempty" yaml:"addAuditNote,omitempty"`
}

// Rule is a single rule in the chain.
type Rule struct {
	ID       string  `json:"id" yaml:"id"`
	Name     string  `json:"name,omitempty" yaml:"name,omitempty"`
	Mode     Mode    `json:"mode" yaml:"mode"`
	Order    int     `json:"order,omitempty" yaml:"order,omitempty"`
	Enabled  *bool   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Match    Matcher `json:"match" yaml:"match"`
	Effects  Effects `json:"effects,omitempty" yaml:"effects,omitempty"`
	Action   string  `json:"action,omitempty" yaml:"action,omitempty"`
	Terminal *bool   `json:"terminal,omitempty" yaml:"terminal,omitempty"`
	Reason   string  `json:"reason,omitempty" yaml:"reason,omitempty"`
}

// IsEnabled reports whether the rule is enabled (default true).
func (r *Rule) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

// IsTerminal returns whether the rule stops chain evaluation. Decide
// rules default to terminal=true; enrich/audit default to false.
func (r *Rule) IsTerminal() bool {
	if r.Terminal != nil {
		return *r.Terminal
	}
	return r.Mode == ModeDecide
}

// Policy is the top-level container.
type Policy struct {
	ID            string `json:"id" yaml:"id"`
	Name          string `json:"name,omitempty" yaml:"name,omitempty"`
	DefaultAction string `json:"defaultAction,omitempty" yaml:"defaultAction,omitempty"`
	// WritableDirs is an operator-managed allowlist of directories whose
	// ordinary mutations may be auto-allowed by rules matching
	// path.writable. The CLI feeds these into the path resolver.
	WritableDirs []string `json:"writableDirs,omitempty" yaml:"writableDirs,omitempty"`
	// SensitivePaths adds secret-like path patterns (prefixes or globs, see
	// paths.MatchSensitive) on top of the built-in list.
	SensitivePaths []string           `json:"sensitivePaths,omitempty" yaml:"sensitivePaths,omitempty"`
	Actions        map[string]*Action `json:"actions" yaml:"actions"`
	Rules          []*Rule            `json:"rules" yaml:"rules"`
}

// EnsureSorted sorts rules by Order ascending while keeping declared
// ordering for ties.
func (p *Policy) EnsureSorted() {
	sort.SliceStable(p.Rules, func(i, j int) bool {
		return p.Rules[i].Order < p.Rules[j].Order
	})
}

// Validate makes a few sanity checks and returns a list of errors.
func (p *Policy) Validate() []error {
	var errs []error
	if p.ID == "" {
		errs = append(errs, fmt.Errorf("policy.id is required"))
	}
	if p.Actions == nil {
		p.Actions = map[string]*Action{}
	}
	// Built-in actions are added if the user did not.
	for name, eff := range map[string]EffectiveAction{
		"allow": EffectAllow,
		"ask":   EffectAsk,
		"deny":  EffectDeny,
	} {
		if _, ok := p.Actions[name]; !ok {
			p.Actions[name] = &Action{Name: name, EffectiveAction: eff, Severity: severityFor(eff)}
		} else if p.Actions[name].Name == "" {
			p.Actions[name].Name = name
		}
	}
	for _, a := range p.Actions {
		if a.EffectiveAction != EffectAllow && a.EffectiveAction != EffectAsk && a.EffectiveAction != EffectDeny {
			errs = append(errs, fmt.Errorf("action %q has invalid effectiveAction %q", a.Name, a.EffectiveAction))
		}
		for _, f := range a.Relaxes {
			if !knownFields[f] || !strings.HasPrefix(f, "context.") {
				errs = append(errs, fmt.Errorf("action %q: relaxes %q is not a context field", a.Name, f))
			}
		}
		if len(a.Relaxes) > 0 && !a.Category {
			errs = append(errs, fmt.Errorf("action %q: relaxes needs category: true", a.Name))
		}
	}
	for _, r := range p.Rules {
		if r.ID == "" {
			errs = append(errs, fmt.Errorf("rule with empty id"))
		}
		if r.Mode == "" {
			r.Mode = ModeDecide
		}
		if r.Mode != ModeEnrich && r.Mode != ModeDecide && r.Mode != ModeAudit {
			errs = append(errs, fmt.Errorf("rule %q invalid mode %q", r.ID, r.Mode))
		}
		if err := r.Match.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("rule %q: %v", r.ID, err))
		}
		if r.Mode == ModeDecide {
			if r.Action == "" {
				errs = append(errs, fmt.Errorf("decide rule %q missing action", r.ID))
			} else if _, ok := p.Actions[r.Action]; !ok {
				errs = append(errs, fmt.Errorf("rule %q references unknown action %q", r.ID, r.Action))
			}
		}
	}
	for _, pat := range p.SensitivePaths {
		if !paths.ValidSensitivePattern(pat) {
			errs = append(errs, fmt.Errorf("sensitivePaths: invalid pattern %q", pat))
		}
	}
	if p.DefaultAction == "" {
		p.DefaultAction = "ask"
	}
	if _, ok := p.Actions[p.DefaultAction]; !ok {
		errs = append(errs, fmt.Errorf("defaultAction %q not in actions", p.DefaultAction))
	}
	return errs
}

func severityFor(e EffectiveAction) int {
	switch e {
	case EffectAllow:
		return 0
	case EffectAsk:
		return 50
	case EffectDeny:
		return 100
	}
	return 0
}

// MatchedRule records that a rule matched a leaf. Effects/Action are
// duplicated here for explainability.
type MatchedRule struct {
	RuleID   string   `json:"ruleId"`
	Mode     Mode     `json:"mode"`
	Effects  *Effects `json:"effects,omitempty"`
	Action   string   `json:"action,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Terminal bool     `json:"terminal,omitempty"`
	// Partial marks an allow rule that cleared only some of the leaf's
	// (operation, path) units; matching continued for the rest.
	Partial bool `json:"partial,omitempty"`
}

// CandidateAction is a possibly-final action produced by a decide rule.
type CandidateAction struct {
	ActionName      string          `json:"action"`
	EffectiveAction EffectiveAction `json:"effectiveAction"`
	Severity        int             `json:"severity"`
	SourceRuleID    string          `json:"sourceRuleId"`
	Reason          string          `json:"reason,omitempty"`
}

// LeafEvaluation holds the per-leaf state and outcome.
type LeafEvaluation struct {
	Command      *ir.Command      `json:"-"`
	Tags         []string         `json:"tags,omitempty"`
	RiskScore    int              `json:"riskScore"`
	AuditNotes   []string         `json:"auditNotes,omitempty"`
	MatchedRules []MatchedRule    `json:"matchedRules,omitempty"`
	Decision     *CandidateAction `json:"decision,omitempty"`
}

// Result is the aggregated outcome for a whole command tree.
type Result struct {
	Decision string `json:"decision"`
	// RuleID is the rule behind Decision; empty when the default action
	// applied.
	RuleID            string           `json:"ruleId,omitempty"`
	EffectiveDecision EffectiveAction  `json:"effectiveDecision"`
	Reason            string           `json:"reason,omitempty"`
	RiskScore         int              `json:"riskScore"`
	Tags              []string         `json:"tags,omitempty"`
	AuditNotes        []string         `json:"auditNotes,omitempty"`
	MatchedRules      []MatchedRule    `json:"matchedRules,omitempty"`
	Operations        []ir.ResourceOp  `json:"operations,omitempty"`
	PerLeaf           []LeafEvaluation `json:"perLeaf,omitempty"`
}
