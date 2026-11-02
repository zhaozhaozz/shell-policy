// Package shellpolicy is the public API of shell-policy for programs that
// embed the engine, such as ShellGate: parse a rule file, switch whole
// categories between allow / ask / deny, and evaluate a command against a
// per-call environment (working directory, writable directories, extra
// sensitive paths) with an explain trace.
//
//	pol, err := shellpolicy.Parse(ruleFile)   // or shellpolicy.Default()
//	pol, err = pol.WithEffects(map[string]shellpolicy.Effect{"ask_privilege": shellpolicy.Deny})
//	res, err := pol.Evaluate("cd /etc && rm -f passwd", shellpolicy.Env{Cwd: dir, Home: home, WritableDirs: []string{dir}})
//
// It is a policy gate, not a sandbox: decisions come from static analysis.
package shellpolicy

import (
	"fmt"
	"sort"

	"github.com/self/shell_permission/docs"
	"github.com/self/shell_permission/internal/analyze"
	"github.com/self/shell_permission/internal/ir"
	"github.com/self/shell_permission/internal/paths"
	"github.com/self/shell_permission/internal/policy"
	"github.com/self/shell_permission/policies"
)

// Effect is the final classification of a command.
type Effect string

const (
	Allow Effect = "allow"
	Ask   Effect = "ask"
	Deny  Effect = "deny"
)

// Valid reports whether e is allow, ask or deny.
func (e Effect) Valid() bool { return e == Allow || e == Ask || e == Deny }

// DefaultYAML returns a copy of the built-in default policy.
func DefaultYAML() []byte { return append([]byte(nil), policies.DefaultYAML...) }

// AuthoringGuide returns a copy of docs/AUTHORING_RULES.md, the guide to the
// rule file syntax (Markdown, Chinese), for programs that show it to users.
func AuthoringGuide() []byte { return append([]byte(nil), docs.AuthoringRules...) }

// Default returns the parsed built-in default policy.
func Default() *Policy {
	p, err := Parse(policies.DefaultYAML)
	if err != nil {
		panic("shellpolicy: built-in default policy is invalid: " + err.Error())
	}
	return p
}

// Policy is a parsed and validated rule file. It is immutable and safe for
// concurrent use.
type Policy struct {
	p *policy.Policy
}

// Parse validates a YAML rule file (see docs/AUTHORING_RULES.md). Unknown
// keys, unknown match fields or operators, invalid regexes and references
// to undefined actions are errors.
func Parse(yaml []byte) (*Policy, error) {
	p, err := policy.Load(yaml)
	if err != nil {
		return nil, err
	}
	return &Policy{p: p}, nil
}

// Action is one named action of a policy.
type Action struct {
	Name     string `json:"name"`
	Effect   Effect `json:"effect"`
	Severity int    `json:"severity"`
	// Rules is the number of enabled decide rules that use the action.
	Rules int `json:"rules"`
}

// Actions lists the named actions, sorted by name.
func (p *Policy) Actions() []Action {
	uses := map[string]int{}
	for _, r := range p.p.Rules {
		if r.Mode == policy.ModeDecide && r.IsEnabled() {
			uses[r.Action]++
		}
	}
	out := make([]Action, 0, len(p.p.Actions))
	for name, a := range p.p.Actions {
		out = append(out, Action{Name: name, Effect: Effect(a.EffectiveAction), Severity: a.Severity, Rules: uses[name]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Action returns one named action.
func (p *Policy) Action(name string) (Action, bool) {
	for _, a := range p.Actions() {
		if a.Name == name {
			return a, true
		}
	}
	return Action{}, false
}

// DefaultAction is the action applied to commands no rule decided.
func (p *Policy) DefaultAction() string { return p.p.DefaultAction }

// WritableDirs are the policy file's writable directories.
func (p *Policy) WritableDirs() []string { return append([]string(nil), p.p.WritableDirs...) }

// SensitivePaths are the policy file's extra sensitive path patterns.
func (p *Policy) SensitivePaths() []string { return append([]string(nil), p.p.SensitivePaths...) }

// WithEffects returns a copy of the policy in which the named actions take
// new effects. This is how a whole category is switched without editing
// rules:
//
//   - ask / deny sets the action's effect, so every rule using it asks or
//     denies;
//   - allow on a deny/ask action disables the rules that use it: that
//     category stops asking or denying and the remaining rules decide. It
//     does not auto-allow everything those rules matched (allowing sudo
//     must not allow `sudo rm -rf ~` outside the writable directories);
//   - the default action (and any action already allowing) takes the effect
//     literally.
//
// Unknown action names and invalid effects are errors.
func (p *Policy) WithEffects(effects map[string]Effect) (*Policy, error) {
	cp := *p.p
	cp.Actions = make(map[string]*policy.Action, len(p.p.Actions))
	for name, a := range p.p.Actions {
		ac := *a
		cp.Actions[name] = &ac
	}
	cp.Rules = make([]*policy.Rule, len(p.p.Rules))
	for i, r := range p.p.Rules {
		rc := *r
		cp.Rules[i] = &rc
	}
	for name, eff := range effects {
		a, ok := cp.Actions[name]
		if !ok {
			return nil, fmt.Errorf("unknown action %q", name)
		}
		if !eff.Valid() {
			return nil, fmt.Errorf("action %q: invalid effect %q", name, eff)
		}
		if eff == Allow && a.EffectiveAction != policy.EffectAllow && name != cp.DefaultAction {
			disabled := false
			for _, r := range cp.Rules {
				if r.Mode == policy.ModeDecide && r.Action == name {
					r.Enabled = &disabled
				}
			}
		}
		a.EffectiveAction = policy.EffectiveAction(eff)
	}
	return &Policy{p: &cp}, nil
}

// ValidSensitivePattern reports whether pattern is a usable sensitive-path
// pattern (see Env.SensitivePaths), so callers can reject it before saving.
func ValidSensitivePattern(pattern string) bool { return paths.ValidSensitivePattern(pattern) }

// Env is the per-call environment a command is evaluated in.
type Env struct {
	// Cwd is the directory the command starts in; empty means unknown, and
	// relative paths are then never inside a writable directory.
	Cwd string
	// Home expands ~ and classifies the home scope.
	Home string
	// WorkspaceRoots are where read-only commands are auto-allowed. When
	// empty, WritableDirs are used.
	WorkspaceRoots []string
	// WritableDirs are where ordinary modifications are auto-allowed; the
	// policy file's writableDirs are added.
	WritableDirs []string
	// SensitivePaths are added to the built-in and policy file patterns:
	// path prefixes or globs matched per path component. "~/.aws/" and
	// "/etc/app/secrets/" are anchored; ".env.*" or "*.key" match at any
	// depth; a match also covers everything below it.
	SensitivePaths []string
}

// Result is the decision for one command.
type Result struct {
	Effect Effect `json:"effect"`
	// Action is the named action that decided, e.g. "ask_privilege", or the
	// policy's default action when no rule decided.
	Action string `json:"action"`
	// RuleID is the rule that decided; empty for the default action.
	RuleID     string      `json:"rule_id,omitempty"`
	Reason     string      `json:"reason,omitempty"`
	RiskScore  int         `json:"risk_score"`
	Tags       []string    `json:"tags,omitempty"`
	Steps      []Step      `json:"steps,omitempty"`
	Operations []Operation `json:"operations,omitempty"`
}

// Step is one rule match in the explain trace.
type Step struct {
	// Command is the simple command (leaf) the rule matched; the whole
	// command for the cross-leaf pass.
	Command string `json:"command"`
	RuleID  string `json:"rule_id"`
	Mode    string `json:"mode"`
	Action  string `json:"action,omitempty"`
	Effect  Effect `json:"effect,omitempty"`
	Reason  string `json:"reason,omitempty"`
	// Partial marks an allow rule that cleared only some operations.
	Partial bool `json:"partial,omitempty"`
}

// Operation is a resource operation the analyzer found.
type Operation struct {
	Type   string `json:"type"`
	Target string `json:"target,omitempty"`
	Paths  []Path `json:"paths,omitempty"`
}

// Path is one classified path of an operation.
type Path struct {
	Raw       string `json:"raw"`
	Absolute  string `json:"absolute,omitempty"`
	Scope     string `json:"scope"`
	Writable  bool   `json:"writable,omitempty"`
	Sensitive bool   `json:"sensitive,omitempty"`
}

// Evaluate parses, analyzes and evaluates command. A command that cannot be
// parsed returns an error; callers should treat it as at least "ask".
func (p *Policy) Evaluate(command string, env Env) (*Result, error) {
	writable := append(append([]string(nil), env.WritableDirs...), p.p.WritableDirs...)
	workspace := env.WorkspaceRoots
	if len(workspace) == 0 {
		workspace = writable
	}
	rsv := &paths.Resolver{
		Cwd:            env.Cwd,
		Home:           env.Home,
		WorkspaceRoots: append([]string(nil), workspace...),
		WritableRoots:  writable,
		SensitivePaths: append(append([]string(nil), env.SensitivePaths...), p.p.SensitivePaths...),
	}
	pr, err := analyze.AnalyzeText(command, rsv)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	res, err := policy.New(p.p).Evaluate(pr.Command)
	if err != nil {
		return nil, err
	}
	out := &Result{
		Effect:    Effect(res.EffectiveDecision),
		Action:    res.Decision,
		Reason:    res.Reason,
		RiskScore: res.RiskScore,
		Tags:      res.Tags,
	}
	out.RuleID = res.RuleID
	for _, leaf := range res.PerLeaf {
		text := leafText(leaf.Command)
		for _, mr := range leaf.MatchedRules {
			out.Steps = append(out.Steps, p.step(text, mr))
		}
	}
	// The cross-leaf pass records its matches only on the whole result.
	if n := countLeafMatches(res); n < len(res.MatchedRules) {
		for _, mr := range res.MatchedRules[n:] {
			out.Steps = append(out.Steps, p.step(command, mr))
		}
	}
	for _, op := range res.Operations {
		o := Operation{Type: string(op.Type), Target: op.Target}
		for _, np := range op.Paths {
			o.Paths = append(o.Paths, Path{Raw: np.Raw, Absolute: np.Absolute, Scope: string(np.Scope), Writable: np.Writable, Sensitive: np.SecretCandidate})
		}
		out.Operations = append(out.Operations, o)
	}
	return out, nil
}

func (p *Policy) step(command string, mr policy.MatchedRule) Step {
	s := Step{Command: command, RuleID: mr.RuleID, Mode: string(mr.Mode), Action: mr.Action, Reason: mr.Reason, Partial: mr.Partial}
	if a, ok := p.p.Actions[mr.Action]; ok && mr.Action != "" {
		s.Effect = Effect(a.EffectiveAction)
	}
	return s
}

func countLeafMatches(res *policy.Result) int {
	n := 0
	for _, leaf := range res.PerLeaf {
		n += len(leaf.MatchedRules)
	}
	return n
}

func leafText(c *ir.Command) string {
	if c == nil {
		return ""
	}
	if c.Source.Text != "" {
		return c.Source.Text
	}
	if c.Simple != nil {
		var s string
		for i, a := range c.Simple.Argv {
			if i > 0 {
				s += " "
			}
			if a.Raw != "" {
				s += a.Raw
			} else {
				s += a.Value
			}
		}
		return s
	}
	return ""
}
