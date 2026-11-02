package policy

import (
	"fmt"
	"log/slog"

	"github.com/self/shell_permission/internal/audit"
	"github.com/self/shell_permission/internal/ir"
)

// Engine runs a Policy against an IR command tree.
type Engine struct {
	Policy *Policy
	// Logger receives leveled diagnostics about the evaluation process
	// (rule matches, final decision). It is never nil; New defaults it to
	// a discard logger so call sites need no nil checks.
	Logger *slog.Logger
}

// New creates an Engine. The policy must already be valid (call
// policy.Validate beforehand if desired).
func New(p *Policy) *Engine {
	return &Engine{Policy: p, Logger: audit.Discard()}
}

// WithLogger sets the diagnostic logger and returns the engine for
// chaining. A nil logger is replaced with a discard logger.
func (e *Engine) WithLogger(l *slog.Logger) *Engine {
	if l == nil {
		l = audit.Discard()
	}
	e.Logger = l
	return e
}

// Evaluate runs the policy and aggregates per-leaf decisions into a
// single Result. The deny > ask > allow rule is used to combine.
func (e *Engine) Evaluate(root *ir.Command) (*Result, error) {
	if root == nil {
		return &Result{Decision: e.Policy.DefaultAction, EffectiveDecision: e.effective(e.Policy.DefaultAction), Reason: "empty command"}, nil
	}
	leaves := ir.Leaves(root)
	if len(leaves) == 0 {
		// Walk found no simple commands (e.g. function definition).
		leaves = []*ir.Command{root}
	}

	res := &Result{}
	var allOps []ir.ResourceOp
	for _, leaf := range leaves {
		le, err := e.evaluateLeaf(leaf)
		if err != nil {
			return nil, err
		}
		res.PerLeaf = append(res.PerLeaf, *le)
		res.MatchedRules = append(res.MatchedRules, le.MatchedRules...)
		res.Tags = mergeUnique(res.Tags, le.Tags)
		res.AuditNotes = mergeUnique(res.AuditNotes, le.AuditNotes)
		if le.RiskScore > res.RiskScore {
			res.RiskScore = le.RiskScore
		}
		if leaf.Simple != nil {
			allOps = append(allOps, leaf.Simple.Operations...)
		}
	}
	res.Operations = allOps

	// Cross-leaf pass: re-run deny/ask rules against a synthetic leaf whose
	// tags/risk are the union of all leaves' so cross-cutting rules (e.g.
	// secret_candidate + network_write) can fire even when the contributing
	// operations live on different leaves. The synthetic leaf has no command,
	// operation or path, so allow rules and catch-all rules (empty match)
	// are skipped: they would decide every multi-leaf command.
	if len(leaves) > 1 {
		merged := &LeafEvaluation{
			Command:   root,
			Tags:      append([]string(nil), res.Tags...),
			RiskScore: res.RiskScore,
		}
		for _, r := range e.Policy.Rules {
			if !r.IsEnabled() || r.Mode != ModeDecide || len(r.Match) == 0 {
				continue
			}
			act, ok := e.Policy.Actions[r.Action]
			if !ok || act.EffectiveAction == EffectAllow {
				continue
			}
			matched, err := r.Match.Eval(merged)
			if err != nil {
				return nil, fmt.Errorf("cross-leaf rule %q: %w", r.ID, err)
			}
			if !matched {
				continue
			}
			merged.Decision = stronger(merged.Decision, &CandidateAction{
				ActionName:      act.Name,
				EffectiveAction: act.EffectiveAction,
				Severity:        act.Severity,
				SourceRuleID:    r.ID,
				Reason:          r.Reason,
			})
			res.MatchedRules = append(res.MatchedRules, MatchedRule{
				RuleID: r.ID, Mode: r.Mode, Action: r.Action,
				Reason: r.Reason, Terminal: r.IsTerminal(),
			})
			if r.IsTerminal() {
				break
			}
		}
		if merged.Decision != nil {
			res.PerLeaf = append(res.PerLeaf, *merged)
		}
	}

	// Aggregate decisions.
	chosen := e.chooseFinal(res.PerLeaf)
	if chosen != nil {
		res.Decision = chosen.ActionName
		res.EffectiveDecision = chosen.EffectiveAction
		res.Reason = chosen.Reason
	} else {
		def := e.Policy.DefaultAction
		res.Decision = def
		res.EffectiveDecision = e.effective(def)
		res.Reason = "no rule matched; default action applied"
	}
	if e.Logger != nil {
		e.Logger.Info("decision",
			"decision", res.Decision, "effective", string(res.EffectiveDecision),
			"risk", res.RiskScore, "leaves", len(leaves), "tags", res.Tags)
	}
	return res, nil
}

func (e *Engine) effective(name string) EffectiveAction {
	if a, ok := e.Policy.Actions[name]; ok {
		return a.EffectiveAction
	}
	return EffectAsk
}

func (e *Engine) severity(name string) int {
	if a, ok := e.Policy.Actions[name]; ok {
		return a.Severity
	}
	return severityFor(EffectAsk)
}

// evaluateLeaf runs the rule chain over one leaf, matching rules per
// (operation, path) unit. Enrich/audit rules and deny/ask decisions fire when
// any unit matches. An allow rule only clears the units it matches, and the
// leaf is allowed once every unit is cleared: a harmless read
// (`cat README.md`) cannot vouch for a write on the same command
// (`> ~/.bashrc`). Later decide rules only see units that are not cleared.
func (e *Engine) evaluateLeaf(leaf *ir.Command) (*LeafEvaluation, error) {
	le := &LeafEvaluation{Command: leaf}
	units := leafUnits(le)
	cleared := make([]bool, len(units))
	open := len(units)
	for _, r := range e.Policy.Rules {
		if !r.IsEnabled() {
			continue
		}
		var act *Action
		decide := r.Mode == ModeDecide && r.Action != ""
		if decide {
			a, ok := e.Policy.Actions[r.Action]
			if !ok {
				return nil, fmt.Errorf("rule %q references unknown action %q", r.ID, r.Action)
			}
			act = a
		}
		hits, err := r.Match.matchUnits(le, units)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		matched := false
		for i := range hits {
			if decide && cleared[i] {
				hits[i] = false
			}
			matched = matched || hits[i]
		}
		if !matched {
			continue
		}
		mr := MatchedRule{
			RuleID:   r.ID,
			Mode:     r.Mode,
			Action:   r.Action,
			Reason:   r.Reason,
			Terminal: r.IsTerminal(),
		}
		// Apply effects (enrich/audit/decide may all carry effects).
		if len(r.Effects.AddTags) > 0 || r.Effects.AddRisk != 0 || r.Effects.AddAuditNote != "" {
			eff := r.Effects
			mr.Effects = &eff
			le.Tags = mergeUnique(le.Tags, r.Effects.AddTags)
			le.RiskScore += r.Effects.AddRisk
			if r.Effects.AddAuditNote != "" {
				le.AuditNotes = append(le.AuditNotes, r.Effects.AddAuditNote)
			}
		}
		// Decide rules set the candidate decision. An ask/deny keeps the
		// strongest one seen so far, so a non-terminal ask is never weakened
		// by a later rule. An allow decides the leaf only once it has no
		// uncleared units left and nothing stronger was decided.
		if decide {
			cand := &CandidateAction{
				ActionName:      act.Name,
				EffectiveAction: act.EffectiveAction,
				Severity:        act.Severity,
				SourceRuleID:    r.ID,
				Reason:          r.Reason,
			}
			if act.EffectiveAction == EffectAllow {
				for i, hit := range hits {
					if hit {
						cleared[i] = true
						open--
					}
				}
				if open > 0 {
					mr.Partial = true
					mr.Terminal = false
				} else if le.Decision == nil {
					le.Decision = cand
				}
			} else {
				le.Decision = stronger(le.Decision, cand)
			}
		}
		le.MatchedRules = append(le.MatchedRules, mr)
		if e.Logger != nil {
			e.Logger.Debug("rule matched",
				"rule", r.ID, "mode", string(r.Mode), "action", r.Action,
				"terminal", mr.Terminal, "partial", mr.Partial, "risk", le.RiskScore)
		}
		if mr.Terminal {
			break
		}
	}
	// No rule decided the leaf (or an allow cleared only part of it): use the
	// default action, so that another leaf's allow cannot carry it.
	if le.Decision == nil {
		def := e.Policy.DefaultAction
		reason := "no rule matched; default action applied"
		if open < len(units) {
			reason = "only part of the command matched an allow rule; default action applied"
		}
		le.Decision = &CandidateAction{
			ActionName:      def,
			EffectiveAction: e.effective(def),
			Severity:        e.severity(def),
			Reason:          reason,
		}
	}
	return le, nil
}

// stronger returns the stronger of two candidate decisions: deny > ask >
// allow, then higher severity; ties keep the earlier one.
func stronger(cur, cand *CandidateAction) *CandidateAction {
	if cur == nil {
		return cand
	}
	if r1, r2 := rank(cur.EffectiveAction), rank(cand.EffectiveAction); r2 != r1 {
		if r2 > r1 {
			return cand
		}
		return cur
	}
	if cand.Severity > cur.Severity {
		return cand
	}
	return cur
}

func rank(a EffectiveAction) int {
	switch a {
	case EffectDeny:
		return 3
	case EffectAsk:
		return 2
	case EffectAllow:
		return 1
	}
	return 0
}

// chooseFinal aggregates per-leaf decisions: deny > ask > allow.
func (e *Engine) chooseFinal(leaves []LeafEvaluation) *CandidateAction {
	var best *CandidateAction
	for i := range leaves {
		if d := leaves[i].Decision; d != nil {
			best = stronger(best, d)
		}
	}
	return best
}

func mergeUnique(into, add []string) []string {
	seen := map[string]bool{}
	for _, x := range into {
		seen[x] = true
	}
	for _, x := range add {
		if !seen[x] {
			into = append(into, x)
			seen[x] = true
		}
	}
	return into
}
