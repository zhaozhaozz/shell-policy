package policy

import (
	"testing"

	"github.com/self/shell_permission/internal/analyze"
	"github.com/self/shell_permission/internal/paths"
)

// aggregationPolicy has no catch-all rule: undecided leaves fall back to
// defaultAction.
const aggregationPolicy = `
policy:
  id: aggregation
  defaultAction: fallback
actions:
  fallback: {effectiveAction: ask, severity: 40}
  ok: {effectiveAction: allow}
  soft_ask: {effectiveAction: ask, severity: 55}
  hard_deny: {effectiveAction: deny, severity: 100}
rules:
  - id: mark-net
    mode: enrich
    match: {operation.type: network_read}
    effects: {addTags: [net]}
  - id: ask-net
    order: 10
    match: {tags: {contains: net}}
    action: soft_ask
    terminal: false
  - id: allow-cat
    order: 20
    match: {command.program: cat}
    action: ok
  - id: allow-curl
    order: 30
    match: {command.program: curl}
    action: ok
  - id: deny-rm
    order: 40
    match: {command.program: rm}
    action: hard_deny
`

func evalWith(t *testing.T, policyYAML, command string) *Result {
	t.Helper()
	pol, err := Load([]byte(policyYAML))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	pr, err := analyze.AnalyzeText(command, &paths.Resolver{Cwd: "/repo", WorkspaceRoots: []string{"/repo"}})
	if err != nil {
		t.Fatalf("AnalyzeText(%q): %v", command, err)
	}
	res, err := New(pol).Evaluate(pr.Command)
	if err != nil {
		t.Fatalf("Evaluate(%q): %v", command, err)
	}
	return res
}

func TestAggregation(t *testing.T) {
	cases := []struct {
		name, command, decision string
	}{
		// Allowed leaves stay allowed when combined; the cross-leaf pass must
		// not turn every multi-command line into a default decision.
		{"two allowed leaves", `cat a && cat b`, "ok"},
		// A leaf no rule decides gets the default action, even when another
		// leaf of the same command was allowed.
		{"undecided leaf uses default", `cat a && make`, "fallback"},
		{"single undecided leaf", `make`, "fallback"},
		// A non-terminal ask is not weakened by a later allow on the same leaf.
		{"non-terminal ask survives allow", `curl https://example.com`, "soft_ask"},
		// The strongest decision across leaves wins.
		{"deny beats ask", `curl https://example.com; rm x`, "hard_deny"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := evalWith(t, aggregationPolicy, tc.command)
			if res.Decision != tc.decision {
				t.Fatalf("decision = %s, want %s; rules=%+v", res.Decision, tc.decision, res.MatchedRules)
			}
		})
	}
}

func TestDefaultPolicyAllowsCombinedReadonlyCommands(t *testing.T) {
	res := evalDefaultPolicy(t, `cat README.md && cat Makefile`)
	if res.EffectiveDecision != EffectAllow {
		t.Fatalf("decision = %s/%s, want allow; rules=%+v", res.Decision, res.EffectiveDecision, res.MatchedRules)
	}
}

func TestSensitivePathsLoadAndValidate(t *testing.T) {
	pol, err := Load([]byte("policy:\n  id: p\n  sensitivePaths: [\"~/.aws/\", \"*.key\"]\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(pol.SensitivePaths) != 2 {
		t.Fatalf("sensitivePaths = %v", pol.SensitivePaths)
	}
	if _, err := Load([]byte("policy:\n  id: p\n  sensitivePaths: [\"[\"]\n")); err == nil {
		t.Fatal("an invalid glob should be rejected")
	}
}
