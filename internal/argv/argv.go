// Package argv parses positional/flag arguments after the AST→IR phase.
//
// The result is intentionally simple: a flat map of flag → value plus a
// list of positional words. Each command spec is responsible for naming
// flags it cares about; unknown flags are still surfaced under their
// raw name so rules can match on them.
package argv

import (
	"strings"

	"github.com/self/shell_permission/internal/ir"
)

// FlagSpec describes a flag understood by a command.
type FlagSpec struct {
	// Names is the list of flag spellings (e.g. "-r", "-R", "--recursive").
	Names []string
	// TakesValue is true for flags that consume the next token (e.g. "-C path").
	TakesValue bool
	// Repeatable allows the same flag to appear multiple times.
	Repeatable bool
}

// Spec describes the flag layout of a command.
type Spec struct {
	// StopAtFirstPositional is true for commands like `find` that mix
	// positionals and flags; we keep argv parsing simple by only
	// recognising flags before the first positional.
	StopAtFirstPositional bool
	Flags                 map[string]FlagSpec
}

// Parsed is the result of argv parsing.
type Parsed struct {
	Program         string
	Args            []ir.ArgValue  // original argv minus program
	Flags           map[string]any // flag_name → value (true | string | []string)
	RawFlags        map[string]any // unrecognised flags by their literal spelling
	Positionals     []ir.ArgValue
	AfterDoubleDash []ir.ArgValue
	HasDynamic      bool
}

// Parse parses argv against a Spec. argv[0] is treated as the program
// and skipped.
func Parse(argv []ir.ArgValue, spec Spec) *Parsed {
	out := &Parsed{
		Flags:    map[string]any{},
		RawFlags: map[string]any{},
	}
	if len(argv) == 0 {
		return out
	}
	out.Program = argv[0].Value
	if argv[0].Confidence != ir.ConfStatic {
		out.HasDynamic = true
	}
	out.Args = argv[1:]

	// Build a name index.
	byName := map[string]string{}
	for canonical, fs := range spec.Flags {
		for _, n := range fs.Names {
			byName[n] = canonical
		}
	}

	pastDoubleDash := false
	seenPositional := false

	for i := 0; i < len(out.Args); i++ {
		a := out.Args[i]
		if a.Confidence != ir.ConfStatic {
			out.HasDynamic = true
		}

		if pastDoubleDash {
			out.AfterDoubleDash = append(out.AfterDoubleDash, a)
			out.Positionals = append(out.Positionals, a)
			continue
		}

		val := a.Value
		if a.Confidence != ir.ConfStatic {
			out.Positionals = append(out.Positionals, a)
			seenPositional = true
			continue
		}

		if val == "--" {
			pastDoubleDash = true
			continue
		}

		if !strings.HasPrefix(val, "-") || val == "-" {
			out.Positionals = append(out.Positionals, a)
			seenPositional = true
			if spec.StopAtFirstPositional {
				// Treat the rest as positionals as well.
				for j := i + 1; j < len(out.Args); j++ {
					out.Positionals = append(out.Positionals, out.Args[j])
					if out.Args[j].Confidence != ir.ConfStatic {
						out.HasDynamic = true
					}
				}
				return out
			}
			continue
		}

		// --long[=value]
		if strings.HasPrefix(val, "--") {
			name := val
			value := ""
			hasInline := false
			if eq := strings.Index(val, "="); eq >= 0 {
				name = val[:eq]
				value = val[eq+1:]
				hasInline = true
			}
			canonical, known := byName[name]
			if !known {
				out.RawFlags[name] = boolOrInline(hasInline, value)
				continue
			}
			fs := spec.Flags[canonical]
			if fs.TakesValue {
				if !hasInline {
					if i+1 < len(out.Args) {
						i++
						value = out.Args[i].Value
						if out.Args[i].Confidence != ir.ConfStatic {
							out.HasDynamic = true
						}
					}
				}
				setFlag(out.Flags, canonical, value, fs.Repeatable)
			} else {
				setFlag(out.Flags, canonical, true, fs.Repeatable)
			}
			continue
		}

		// -short cluster: e.g. -rf, -fR, -fvR, or -p value
		// We attempt to split into single-letter flags. If a letter is
		// known and TakesValue, we consume the rest of the token (or the
		// next token) as its value.
		consumedNext := false
		letters := val[1:]
		for li := 0; li < len(letters); li++ {
			letter := "-" + string(letters[li])
			canonical, known := byName[letter]
			if !known {
				out.RawFlags[letter] = true
				continue
			}
			fs := spec.Flags[canonical]
			if fs.TakesValue {
				rest := letters[li+1:]
				value := ""
				if rest != "" {
					value = rest
				} else if i+1 < len(out.Args) {
					i++
					consumedNext = true
					value = out.Args[i].Value
					if out.Args[i].Confidence != ir.ConfStatic {
						out.HasDynamic = true
					}
				}
				setFlag(out.Flags, canonical, value, fs.Repeatable)
				break
			}
			setFlag(out.Flags, canonical, true, fs.Repeatable)
		}
		_ = consumedNext

		// If a positional has been observed and StopAtFirstPositional, we
		// already returned above.
		if seenPositional && spec.StopAtFirstPositional {
			return out
		}
	}
	return out
}

func setFlag(m map[string]any, name string, val any, repeatable bool) {
	if !repeatable {
		m[name] = val
		return
	}
	prev, ok := m[name]
	if !ok {
		m[name] = []any{val}
		return
	}
	if list, ok := prev.([]any); ok {
		m[name] = append(list, val)
		return
	}
	m[name] = []any{prev, val}
}

func boolOrInline(hasInline bool, value string) any {
	if hasInline {
		return value
	}
	return true
}
