package policy

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/self/shell_permission/internal/ir"
)

// Matcher is a tree of conditions evaluated against a leaf state.
//
// We use a YAML-friendly map representation so users can write rules
// directly. Boolean combinators ("all", "any", "not") and field
// matchers ("equals", "in", "regex", ...) are supported.
type Matcher map[string]any

// matchCtx is the data the matcher sees.
type matchCtx struct {
	leaf  *LeafEvaluation
	op    *ir.ResourceOp     // current op being matched against
	path  *ir.NormalizedPath // current path of op; nil when op has none
	cmd   *ir.Command
	tags  map[string]bool
	flags map[string]any
}

// matchUnit is one (operation, path) pair of a leaf. Rules are matched per
// unit so that path.scope is checked against every path of an operation
// (`cat README.md /etc/passwd`), not only the first one.
type matchUnit struct {
	op   *ir.ResourceOp
	path *ir.NormalizedPath
}

// leafUnits expands a leaf into its match units. A leaf with no operations
// yields one empty pseudo-unit so context-only rules still fire.
func leafUnits(leaf *LeafEvaluation) []matchUnit {
	if leaf.Command == nil || leaf.Command.Simple == nil || len(leaf.Command.Simple.Operations) == 0 {
		return []matchUnit{{}}
	}
	var units []matchUnit
	for i := range leaf.Command.Simple.Operations {
		op := &leaf.Command.Simple.Operations[i]
		if len(op.Paths) == 0 {
			units = append(units, matchUnit{op: op})
			continue
		}
		for j := range op.Paths {
			units = append(units, matchUnit{op: op, path: &op.Paths[j]})
		}
	}
	return units
}

// Eval returns true if the matcher matches at least one unit of the leaf.
func (m Matcher) Eval(leaf *LeafEvaluation) (bool, error) {
	hits, err := m.matchUnits(leaf, leafUnits(leaf))
	if err != nil {
		return false, err
	}
	for _, hit := range hits {
		if hit {
			return true, nil
		}
	}
	return false, nil
}

// matchUnits reports, for each unit, whether the matcher matches it.
func (m Matcher) matchUnits(leaf *LeafEvaluation, units []matchUnit) ([]bool, error) {
	tags := map[string]bool{}
	for _, t := range leaf.Tags {
		tags[t] = true
	}
	flags := map[string]any{}
	if leaf.Command != nil && leaf.Command.Simple != nil && leaf.Command.Simple.Flags != nil {
		flags = leaf.Command.Simple.Flags
	}
	hits := make([]bool, len(units))
	for i, u := range units {
		ctx := &matchCtx{leaf: leaf, op: u.op, path: u.path, cmd: leaf.Command, tags: tags, flags: flags}
		ok, err := evalNode(m, ctx)
		if err != nil {
			return nil, err
		}
		hits[i] = ok
	}
	return hits, nil
}

func evalNode(m Matcher, ctx *matchCtx) (bool, error) {
	if len(m) == 0 {
		return true, nil
	}
	for k, v := range m {
		ok, err := evalKey(k, v, ctx)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func evalKey(key string, v any, ctx *matchCtx) (bool, error) {
	switch key {
	case "all":
		return evalCombinator(v, ctx, true)
	case "any":
		return evalCombinator(v, ctx, false)
	case "not":
		ok, err := evalAsMatcher(v, ctx)
		if err != nil {
			return false, err
		}
		return !ok, nil
	}
	// Field matcher: key is a path like "command.program" or "tags".
	field := key
	var cond map[string]any
	switch x := v.(type) {
	case map[string]any:
		cond = x
	case Matcher:
		cond = map[string]any(x)
	default:
		// Allow shorthand: { foo: "bar" } means foo equals "bar".
		cond = map[string]any{"equals": v}
	}
	return evalField(field, cond, ctx)
}

func evalCombinator(v any, ctx *matchCtx, andMode bool) (bool, error) {
	list, ok := v.([]any)
	if !ok {
		return false, fmt.Errorf("combinator expects list, got %T", v)
	}
	for _, item := range list {
		ok, err := evalAsMatcher(item, ctx)
		if err != nil {
			return false, err
		}
		if andMode && !ok {
			return false, nil
		}
		if !andMode && ok {
			return true, nil
		}
	}
	return andMode, nil
}

func evalAsMatcher(v any, ctx *matchCtx) (bool, error) {
	switch m := v.(type) {
	case map[string]any:
		return evalNode(Matcher(m), ctx)
	case Matcher:
		return evalNode(m, ctx)
	case map[any]any:
		conv := make(Matcher, len(m))
		for k, vv := range m {
			conv[fmt.Sprint(k)] = vv
		}
		return evalNode(conv, ctx)
	}
	return false, fmt.Errorf("expected matcher, got %T", v)
}

// evalField looks up a field on the current ctx and applies cond to it.
func evalField(field string, cond map[string]any, ctx *matchCtx) (bool, error) {
	val, ok := lookupField(field, ctx)
	for op, want := range cond {
		matched, err := applyOp(op, val, ok, want)
		if err != nil {
			return false, fmt.Errorf("field %q op %q: %w", field, op, err)
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}

// lookupField is the (small) field language. It returns the value (or
// nil) and a bool reporting whether the field was present.
func lookupField(field string, ctx *matchCtx) (any, bool) {
	switch {
	case field == "tags":
		return ctx.leaf.Tags, true
	case field == "riskScore":
		return ctx.leaf.RiskScore, true
	case field == "command.program":
		if ctx.cmd != nil && ctx.cmd.Simple != nil {
			return ctx.cmd.Simple.NormalizedProgram, ctx.cmd.Simple.NormalizedProgram != ""
		}
	case field == "command.subcommand":
		if ctx.cmd != nil && ctx.cmd.Simple != nil {
			return ctx.cmd.Simple.Subcommand, len(ctx.cmd.Simple.Subcommand) > 0
		}
	case field == "command.subcommandString":
		if ctx.cmd != nil && ctx.cmd.Simple != nil {
			return strings.Join(ctx.cmd.Simple.Subcommand, " "), len(ctx.cmd.Simple.Subcommand) > 0
		}
	case field == "command.hasAssignments":
		// NAME=value before the program changes its environment, which can
		// change what a "read-only" tool does (RIPGREP_CONFIG_PATH, ...).
		if ctx.cmd != nil && ctx.cmd.Simple != nil {
			return len(ctx.cmd.Simple.Assignments) > 0, true
		}
	case field == "command.hasDynamicArgs":
		if ctx.cmd != nil && ctx.cmd.Simple != nil {
			return ctx.cmd.Simple.HasDynamicArgs, true
		}
	case field == "command.wrapperType":
		if ctx.cmd != nil && ctx.cmd.Simple != nil && ctx.cmd.Simple.Wrapper != nil {
			return ctx.cmd.Simple.Wrapper.Type, true
		}
	case strings.HasPrefix(field, "argv["):
		// argv[0] is the program; argv[1] etc.
		idx := 0
		fmt.Sscanf(field, "argv[%d]", &idx)
		if ctx.cmd != nil && ctx.cmd.Simple != nil && idx < len(ctx.cmd.Simple.Argv) {
			return ctx.cmd.Simple.Argv[idx].Value, true
		}
	case field == "argv":
		if ctx.cmd != nil && ctx.cmd.Simple != nil {
			out := make([]string, 0, len(ctx.cmd.Simple.Argv))
			for _, a := range ctx.cmd.Simple.Argv {
				out = append(out, a.Value)
			}
			return out, true
		}
	case strings.HasPrefix(field, "flags."):
		name := strings.TrimPrefix(field, "flags.")
		if v, ok := ctx.flags[name]; ok {
			return v, true
		}
		return nil, false
	case strings.HasPrefix(field, "flags["):
		name := strings.TrimSuffix(strings.TrimPrefix(field, "flags["), "]")
		name = strings.Trim(name, `"'`)
		if v, ok := ctx.flags[name]; ok {
			return v, true
		}
		return nil, false
	case field == "operation.type":
		if ctx.op != nil {
			return string(ctx.op.Type), true
		}
	case field == "operation.target":
		if ctx.op != nil {
			return ctx.op.Target, ctx.op.Target != ""
		}
	case field == "operation.dynamic":
		if ctx.op != nil {
			return ctx.op.Dynamic, true
		}
	case field == "path.scope":
		if ctx.path != nil {
			return string(ctx.path.Scope), true
		}
	case field == "path.secretPossible":
		// Per (operation, path) unit: "cat README.md *" only has the glob
		// as a possible secret read.
		if ctx.path != nil {
			return ctx.path.SecretPossible, true
		}
		if ctx.op != nil {
			for _, p := range ctx.op.Paths {
				if p.SecretPossible {
					return true, true
				}
			}
			return false, true
		}
	case field == "path.secretCandidate":
		if ctx.op != nil {
			for _, p := range ctx.op.Paths {
				if p.SecretCandidate {
					return true, true
				}
			}
			return false, true
		}
	case field == "path.writable":
		// True only when the operation has at least one path and every
		// path falls inside a configured writable root. This keeps
		// auto-allow conservative: a mix of writable and non-writable
		// targets does not qualify.
		if ctx.op != nil {
			if len(ctx.op.Paths) == 0 {
				return false, true
			}
			for _, p := range ctx.op.Paths {
				if !p.Writable {
					return false, true
				}
			}
			return true, true
		}
	case field == "path.absolute":
		if ctx.path != nil {
			return ctx.path.Absolute, ctx.path.Absolute != ""
		}
	case field == "path.normalized" || field == "path.normalizedRegex":
		// path.normalizedRegex is the older spelling; use `regex` on it.
		if ctx.path != nil {
			return ctx.path.Normalized, ctx.path.Normalized != ""
		}
	case field == "path.raw" || field == "path.rawRegex":
		if ctx.path != nil {
			return ctx.path.Raw, true
		}
	case field == "context.inPipeline":
		if ctx.cmd != nil {
			return ctx.cmd.Context.InPipeline, true
		}
	case field == "context.inSubshell":
		if ctx.cmd != nil {
			return ctx.cmd.Context.InSubshell, true
		}
	case field == "context.inCommandSubstitution":
		if ctx.cmd != nil {
			return ctx.cmd.Context.InCommandSubstitution, true
		}
	case field == "context.inRemoteCommand":
		if ctx.cmd != nil {
			return ctx.cmd.Context.InRemoteCommand, true
		}
	case field == "context.remoteHost":
		if ctx.cmd != nil {
			return ctx.cmd.Context.RemoteHost, ctx.cmd.Context.RemoteHost != ""
		}
	case field == "context.inContainerCommand":
		if ctx.cmd != nil {
			return ctx.cmd.Context.InContainerCommand, true
		}
	case field == "context.privilegeEscalated":
		if ctx.cmd != nil {
			return ctx.cmd.Context.PrivilegeEscalated, true
		}
	case field == "context.inFunction":
		if ctx.cmd != nil {
			return ctx.cmd.Context.InFunction, true
		}
	case field == "context.background":
		if ctx.cmd != nil {
			return ctx.cmd.Context.Background, true
		}
	}
	return nil, false
}

func applyOp(op string, val any, present bool, want any) (bool, error) {
	switch op {
	case "exists":
		w, _ := want.(bool)
		return present == w, nil
	case "equals":
		if !present {
			return false, nil
		}
		return equalsAny(val, want), nil
	case "notEquals":
		if !present {
			return true, nil
		}
		return !equalsAny(val, want), nil
	case "in":
		if !present {
			return false, nil
		}
		list, ok := want.([]any)
		if !ok {
			return false, fmt.Errorf("'in' expects list")
		}
		for _, item := range list {
			if equalsAny(val, item) {
				return true, nil
			}
		}
		return false, nil
	case "notIn":
		if !present {
			return true, nil
		}
		list, ok := want.([]any)
		if !ok {
			return false, fmt.Errorf("'notIn' expects list")
		}
		for _, item := range list {
			if equalsAny(val, item) {
				return false, nil
			}
		}
		return true, nil
	case "contains":
		return containsAny(val, want), nil
	case "containsAll":
		list, ok := want.([]any)
		if !ok {
			return false, fmt.Errorf("'containsAll' expects list")
		}
		for _, item := range list {
			if !containsAny(val, item) {
				return false, nil
			}
		}
		return true, nil
	case "containsAny":
		list, ok := want.([]any)
		if !ok {
			return false, fmt.Errorf("'containsAny' expects list")
		}
		for _, item := range list {
			if containsAny(val, item) {
				return true, nil
			}
		}
		return false, nil
	case "regex":
		s, ok := toString(val)
		if !ok {
			return false, nil
		}
		pattern, ok := want.(string)
		if !ok {
			return false, fmt.Errorf("'regex' expects string")
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, err
		}
		return re.MatchString(s), nil
	case "prefix":
		// equals-as-prefix-of-list
		switch x := val.(type) {
		case []string:
			list, ok := want.([]any)
			if !ok {
				return false, fmt.Errorf("'prefix' expects list")
			}
			if len(list) > len(x) {
				return false, nil
			}
			for i, item := range list {
				if !equalsAny(x[i], item) {
					return false, nil
				}
			}
			return true, nil
		}
		if s, ok := toString(val); ok {
			ws, _ := want.(string)
			return strings.HasPrefix(s, ws), nil
		}
		return false, nil
	case "greaterThanOrEqual":
		return numCompare(val, want, ">=")
	case "greaterThan":
		return numCompare(val, want, ">")
	case "lessThanOrEqual":
		return numCompare(val, want, "<=")
	case "lessThan":
		return numCompare(val, want, "<")
	}
	return false, fmt.Errorf("unknown op %q", op)
}

func equalsAny(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if reflect.DeepEqual(a, b) {
		return true
	}
	// Allow []string vs []any{string}.
	if as, ok := a.([]string); ok {
		if bs, ok := b.([]any); ok {
			if len(as) != len(bs) {
				return false
			}
			for i := range as {
				if !equalsAny(as[i], bs[i]) {
					return false
				}
			}
			return true
		}
	}
	// Numeric coercion.
	an, aok := toNumber(a)
	bn, bok := toNumber(b)
	if aok && bok {
		return an == bn
	}
	// String coercion.
	if sa, ok := toString(a); ok {
		if sb, ok := toString(b); ok {
			return sa == sb
		}
	}
	// JSON compare as fallback.
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

func containsAny(haystack, needle any) bool {
	switch h := haystack.(type) {
	case []string:
		for _, x := range h {
			if equalsAny(x, needle) {
				return true
			}
		}
	case []any:
		for _, x := range h {
			if equalsAny(x, needle) {
				return true
			}
		}
	case string:
		s, ok := toString(needle)
		if !ok {
			return false
		}
		return strings.Contains(h, s)
	}
	return false
}

func toString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case fmt.Stringer:
		return x.String(), true
	}
	return "", false
}

func toNumber(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case float32:
		return float64(x), true
	case float64:
		return x, true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

func numCompare(a, b any, op string) (bool, error) {
	an, aok := toNumber(a)
	bn, bok := toNumber(b)
	if !aok || !bok {
		return false, fmt.Errorf("numeric compare needs numbers")
	}
	switch op {
	case ">":
		return an > bn, nil
	case ">=":
		return an >= bn, nil
	case "<":
		return an < bn, nil
	case "<=":
		return an <= bn, nil
	}
	return false, fmt.Errorf("bad op %q", op)
}

// knownFields are the exact field names lookupField understands; argv[N],
// flags.<name> and flags["--name"] are accepted by prefix.
var knownFields = map[string]bool{
	"tags": true, "riskScore": true, "argv": true,
	"command.program": true, "command.subcommand": true, "command.subcommandString": true,
	"command.hasDynamicArgs": true, "command.wrapperType": true, "command.hasAssignments": true,
	"operation.type": true, "operation.target": true, "operation.dynamic": true,
	"path.scope": true, "path.secretCandidate": true, "path.secretPossible": true, "path.writable": true, "path.absolute": true,
	"path.normalized": true, "path.normalizedRegex": true, "path.raw": true, "path.rawRegex": true,
	"context.inPipeline": true, "context.inSubshell": true, "context.inCommandSubstitution": true,
	"context.inRemoteCommand": true, "context.remoteHost": true, "context.inContainerCommand": true,
	"context.privilegeEscalated": true, "context.inFunction": true, "context.background": true,
}

var knownOps = map[string]bool{
	"exists": true, "equals": true, "notEquals": true, "in": true, "notIn": true,
	"contains": true, "containsAll": true, "containsAny": true, "regex": true, "prefix": true,
	"greaterThanOrEqual": true, "greaterThan": true, "lessThanOrEqual": true, "lessThan": true,
}

// Validate checks field names, operators and regexes so a typo fails when
// the policy is loaded instead of silently never matching.
func (m Matcher) Validate() error {
	return validateNode(map[string]any(m))
}

func validateNode(m map[string]any) error {
	for key, v := range m {
		switch key {
		case "all", "any":
			list, ok := v.([]any)
			if !ok {
				return fmt.Errorf("%q expects a list", key)
			}
			for _, item := range list {
				sub, ok := asMap(item)
				if !ok {
					return fmt.Errorf("%q items must be matchers", key)
				}
				if err := validateNode(sub); err != nil {
					return err
				}
			}
			continue
		case "not":
			sub, ok := asMap(v)
			if !ok {
				return fmt.Errorf("%q expects a matcher", key)
			}
			if err := validateNode(sub); err != nil {
				return err
			}
			continue
		}
		if !knownFields[key] && !strings.HasPrefix(key, "argv[") && !strings.HasPrefix(key, "flags.") && !strings.HasPrefix(key, "flags[") {
			return fmt.Errorf("unknown field %q", key)
		}
		cond, ok := asMap(v)
		if !ok {
			continue // shorthand: field: value
		}
		for op, want := range cond {
			if !knownOps[op] {
				return fmt.Errorf("field %q: unknown operator %q", key, op)
			}
			if op == "regex" {
				pattern, ok := want.(string)
				if !ok {
					return fmt.Errorf("field %q: regex expects a string", key)
				}
				if _, err := regexp.Compile(pattern); err != nil {
					return fmt.Errorf("field %q: %v", key, err)
				}
			}
		}
	}
	return nil
}

func asMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case Matcher:
		return map[string]any(m), true
	}
	return nil, false
}
