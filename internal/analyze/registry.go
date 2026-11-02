package analyze

import (
	"github.com/self/shell_permission/internal/argv"
	"github.com/self/shell_permission/internal/ir"
	"github.com/self/shell_permission/internal/paths"
)

// commandSpec is the internal representation of a built-in command spec.
type commandSpec struct {
	Argv       argv.Spec
	Subcommand func(*argv.Parsed) []string
	Operations func(*ir.Command, *argv.Parsed, *paths.Resolver) []ir.ResourceOp
}

// registry holds every command spec the engine knows about. It is
// populated in init blocks of the spec_*.go files.
var registry = map[string]*commandSpec{}

func register(programs []string, spec *commandSpec) {
	for _, p := range programs {
		registry[p] = spec
	}
}

// pathsFromArgs converts every static argv positional into a normalized
// path. Dynamic positionals are still recorded but flagged.
func pathsFromArgs(args []ir.ArgValue, r *paths.Resolver) []ir.NormalizedPath {
	out := make([]ir.NormalizedPath, 0, len(args))
	for _, a := range args {
		out = append(out, r.Resolve(a))
	}
	return out
}

// listingPaths resolves the operands of a command that only reveals names
// and metadata (ls, stat): a glob that may expand to a secret-like name is
// not a possible secret read there.
func listingPaths(args []ir.ArgValue, r *paths.Resolver) []ir.NormalizedPath {
	out := pathsFromArgs(args, r)
	for i := range out {
		out[i].SecretPossible = false
	}
	return out
}

// boolFlag returns true if a flag is set to a truthy value.
func boolFlag(p *argv.Parsed, name string) bool {
	v, ok := p.Flags[name]
	if !ok {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	default:
		return true
	}
}

// stringFlag returns the string value of a flag.
func stringFlag(p *argv.Parsed, name string) string {
	v, ok := p.Flags[name]
	if !ok {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// stringListFlag returns repeated flag values as []string.
func stringListFlag(p *argv.Parsed, name string) []string {
	v, ok := p.Flags[name]
	if !ok {
		return nil
	}
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
