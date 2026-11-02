package analyze

import (
	"strings"

	"github.com/self/shell_permission/internal/argv"
	"github.com/self/shell_permission/internal/ir"
	"github.com/self/shell_permission/internal/paths"
)

// sensitiveVars are shell variables whose value changes what later commands
// execute or where they act: the policy analyzed `ls` assuming the normal
// PATH, `~` assuming the real HOME, and so on. Assigning them is recorded as
// a shell_config operation so it is never auto-allowed as a harmless builtin.
var sensitiveVars = map[string]bool{
	"PATH": true, "CDPATH": true, "HOME": true, "PWD": true, "OLDPWD": true, "IFS": true,
	"PROMPT_COMMAND": true, "PS0": true, "PS1": true, "PS2": true, "PS3": true, "PS4": true,
	"PROMPT": true, "RPROMPT": true, "BASH_ENV": true, "ENV": true, "ZDOTDIR": true,
	"SHELLOPTS": true, "BASHOPTS": true, "GLOBIGNORE": true, "FPATH": true,
	"precmd_functions": true, "preexec_functions": true, "chpwd_functions": true,
	"LD_PRELOAD": true, "LD_LIBRARY_PATH": true, "LD_AUDIT": true,
	"DYLD_INSERT_LIBRARIES": true, "DYLD_LIBRARY_PATH": true,
	// Programs that tools start on their own: a pager, editor, diff or ssh
	// command makes `git log` or `less` run anything.
	"PAGER": true, "GIT_PAGER": true, "MANPAGER": true, "SYSTEMD_PAGER": true, "LESSOPEN": true, "LESSCLOSE": true,
	"EDITOR": true, "VISUAL": true, "GIT_EDITOR": true, "GIT_SEQUENCE_EDITOR": true, "GIT_EXTERNAL_DIFF": true,
	"GIT_SSH": true, "GIT_SSH_COMMAND": true, "GIT_ASKPASS": true, "SSH_ASKPASS": true, "GIT_EXEC_PATH": true,
	"GIT_TEMPLATE_DIR": true, "BROWSER": true, "RIPGREP_CONFIG_PATH": true, "GCONV_PATH": true,
	"PERL5OPT": true, "PERL5LIB": true, "PYTHONSTARTUP": true, "NODE_OPTIONS": true, "RUBYOPT": true,
}

// isSensitiveVar also covers families of variables: GIT_CONFIG*, which
// inject git configuration (core.pager, hooks ...).
func isSensitiveVar(name string) bool {
	return sensitiveVars[name] || strings.HasPrefix(name, "GIT_CONFIG")
}

// shellConfigOp records a change to shell state; target names what changed.
func shellConfigOp(c *ir.Command, target string) ir.ResourceOp {
	return ir.ResourceOp{Type: ir.OpShellConfig, Target: target, Confidence: confOf(c.Simple), Context: c.Context}
}

// assignmentOps flags leading `NAME=value` words that set a sensitive
// variable, for the command itself or (without a program) for the shell.
func assignmentOps(c *ir.Command) []ir.ResourceOp {
	var ops []ir.ResourceOp
	for _, as := range c.Simple.Assignments {
		if isSensitiveVar(as.Name) {
			ops = append(ops, shellConfigOp(c, as.Name))
		}
	}
	return ops
}

// varNameOps checks the NAME[=value] arguments of export / declare / unset.
// An argument whose name is not static may name anything, so it counts as
// sensitive; a static name with a dynamic value (FOO=$BAR) does not.
func varNameOps(c *ir.Command, args []ir.ArgValue) []ir.ResourceOp {
	var ops []ir.ResourceOp
	for _, a := range args {
		name, _, _ := strings.Cut(a.Value, "=")
		name = strings.TrimSuffix(name, "+") // NAME+=value
		if a.Confidence == ir.ConfDynamic || strings.Contains(name, "\x00") {
			// The variable name itself is not known statically.
			ops = append(ops, shellConfigOp(c, a.Raw))
			continue
		}
		if strings.HasPrefix(name, "-") || strings.HasPrefix(name, "+") {
			continue // option such as -x or +x
		}
		if isSensitiveVar(name) {
			ops = append(ops, shellConfigOp(c, name))
		}
	}
	return ops
}

func noOps(*ir.Command, *argv.Parsed, *paths.Resolver) []ir.ResourceOp { return nil }

func init() {
	// Builtins without file, network or process effects. Their working
	// directory effect (cd, pushd, popd) is tracked by the analyzer walk.
	register([]string{
		"cd", "chdir", "pushd", "popd", "dirs", "pwd", "true", "false", ":",
		"test", "[", "[[", "((", "let", "exit", "logout", "wait", "jobs",
	}, &commandSpec{Argv: argv.Spec{}, Operations: noOps})

	register([]string{"export", "declare", "typeset", "readonly", "local", "unset"}, &commandSpec{
		Argv: argv.Spec{},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			return varNameOps(c, c.Simple.Argv[1:])
		},
	})

	// Definitions that run code later: aliases, traps, hashed command paths,
	// loadable builtins and key bindings that execute commands.
	register([]string{"alias"}, &commandSpec{
		Argv: argv.Spec{},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			for _, a := range c.Simple.Argv[1:] {
				if a.Confidence != ir.ConfStatic || strings.Contains(a.Value, "=") {
					return []ir.ResourceOp{shellConfigOp(c, "alias")}
				}
			}
			return nil // listing aliases
		},
	})
	register([]string{"trap"}, &commandSpec{
		Argv: argv.Spec{},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			args := c.Simple.Argv[1:]
			if len(args) == 0 || len(args) == 1 && args[0].Confidence == ir.ConfStatic && (args[0].Value == "-l" || args[0].Value == "-p") {
				return nil // listing traps
			}
			return []ir.ResourceOp{shellConfigOp(c, "trap")}
		},
	})
	register([]string{"hash"}, &commandSpec{
		Argv: argv.Spec{},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			if hasStaticArg(c.Simple.Argv[1:], "-p") {
				return []ir.ResourceOp{shellConfigOp(c, "hash")}
			}
			return nil
		},
	})
	register([]string{"enable", "bind"}, &commandSpec{
		Argv: argv.Spec{},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			if len(c.Simple.Argv) > 1 {
				return []ir.ResourceOp{shellConfigOp(c, c.Simple.Program.Value)}
			}
			return nil
		},
	})
}
