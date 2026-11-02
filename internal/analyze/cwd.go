package analyze

import (
	"path/filepath"
	"strings"

	"github.com/self/shell_permission/internal/ir"
)

// cwdState is the analyzer's view of the shell's working directory while it
// walks a command in execution order. known=false means the directory cannot
// be determined statically (cd to a dynamic target, popd, a cd that may have
// failed, ...); relative paths then resolve to scope "unknown".
type cwdState struct {
	dir   string
	known bool
}

var unknownCwd = cwdState{}

func knownCwd(dir string) cwdState { return cwdState{dir: dir, known: true} }

// merge returns the state both branches agree on, or unknown.
func (s cwdState) merge(o cwdState) cwdState {
	if s == o {
		return s
	}
	return unknownCwd
}

// cwdFlow is the working directory after a node ran: succ when the node
// succeeded (what `&&` continues with), fail when it failed (what `||`
// continues with). `;` continues with either, so `cd dir; rm x` cannot vouch
// for where x is: the cd may have failed.
type cwdFlow struct {
	succ, fail cwdState
}

// any is the directory whatever the node's exit status.
func (f cwdFlow) any() cwdState { return f.succ.merge(f.fail) }

func unchanged(s cwdState) cwdFlow { return cwdFlow{succ: s, fail: s} }

// changeTo builds the flow of a command that switches to target on success
// and leaves the directory untouched on failure.
func changeTo(in, target cwdState) cwdFlow {
	return cwdFlow{succ: target, fail: in}
}

// resolveDir resolves a cd-style target against the current state.
func (a *Analyzer) resolveDir(in cwdState, arg ir.ArgValue) cwdState {
	if arg.Confidence != ir.ConfStatic || containsGlobChar(arg.Value) {
		return unknownCwd
	}
	v := arg.Value
	switch {
	case v == "~" || strings.HasPrefix(v, "~/"):
		if a.home() == "" {
			return unknownCwd
		}
		return knownCwd(filepath.Clean(filepath.Join(a.home(), strings.TrimPrefix(v, "~"))))
	case strings.HasPrefix(v, "~"):
		return unknownCwd // ~user
	case filepath.IsAbs(v):
		return knownCwd(filepath.Clean(v))
	case !in.known:
		return unknownCwd
	}
	return knownCwd(filepath.Clean(filepath.Join(in.dir, v)))
}

func (a *Analyzer) home() string {
	if a.Resolver == nil {
		return ""
	}
	return a.Resolver.Home
}

func containsGlobChar(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// cwdEffect computes how a (non-wrapper) simple command changes the working
// directory of the shell it runs in.
func (a *Analyzer) cwdEffect(c *ir.Command, in cwdState) cwdFlow {
	sc := c.Simple
	if sc == nil || len(sc.Argv) == 0 {
		return unchanged(in)
	}
	if sc.Program.Confidence != ir.ConfStatic {
		// A dynamic program may be cd, eval or a shell function.
		return cwdFlow{}
	}
	args := sc.Argv[1:]
	switch sc.Program.Value {
	case "cd", "chdir":
		args = skipDirFlags(args) // -L -P -e -@
		switch len(args) {
		case 0:
			return changeTo(in, a.resolveDir(in, ir.ArgValue{Value: "~", Confidence: ir.ConfStatic}))
		case 1:
			if args[0].Confidence == ir.ConfStatic && args[0].Value == "-" {
				return cwdFlow{} // OLDPWD
			}
			return changeTo(in, a.resolveDir(in, args[0]))
		}
		return cwdFlow{} // zsh `cd old new` substitution
	case "pushd":
		if hasStaticArg(args, "-n") {
			return unchanged(in) // only manipulates the stack
		}
		args = skipDirFlags(args)
		if len(args) != 1 || isStackIndex(args[0]) {
			return cwdFlow{} // swap or rotate the directory stack
		}
		return changeTo(in, a.resolveDir(in, args[0]))
	case "popd":
		if hasStaticArg(args, "-n") {
			return unchanged(in)
		}
		return cwdFlow{}
	case "source", ".", "eval":
		// Runs code in the current shell that may change directory. eval with
		// static text is unwrapped as a wrapper before reaching here.
		return cwdFlow{}
	}
	return unchanged(in)
}

// skipDirFlags drops leading option words of cd/pushd ("--" ends them).
func skipDirFlags(args []ir.ArgValue) []ir.ArgValue {
	for len(args) > 0 && args[0].Confidence == ir.ConfStatic && strings.HasPrefix(args[0].Value, "-") && args[0].Value != "-" {
		if isStackIndex(args[0]) {
			break
		}
		if args[0].Value == "--" {
			return args[1:]
		}
		args = args[1:]
	}
	return args
}

// isStackIndex matches pushd/popd stack rotations such as +1 or -2.
func isStackIndex(a ir.ArgValue) bool {
	if a.Confidence != ir.ConfStatic || len(a.Value) < 2 || (a.Value[0] != '+' && a.Value[0] != '-') {
		return false
	}
	for _, r := range a.Value[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func hasStaticArg(args []ir.ArgValue, v string) bool {
	for _, a := range args {
		if a.Confidence == ir.ConfStatic && a.Value == v {
			return true
		}
	}
	return false
}

// changesCwd reports whether a subtree contains anything that may change the
// shell's directory. Loops and conditionals use it: a cd inside a loop body
// also affects the commands before it on the next iteration.
func changesCwd(c *ir.Command) bool {
	found := false
	ir.Walk(c, func(n *ir.Command) {
		if found || n.Simple == nil || len(n.Simple.Argv) == 0 {
			return
		}
		argv := n.Simple.Argv
		// `command cd`, `builtin cd` and `time cd` still run in this shell.
		for len(argv) > 1 && argv[0].Confidence == ir.ConfStatic && inShellWrappers[argv[0].Value] {
			argv = argv[1:]
		}
		if argv[0].Confidence != ir.ConfStatic || cwdCommands[argv[0].Value] {
			found = true
		}
	})
	return found
}

// cwdCommands may change the directory of the shell that runs them.
var cwdCommands = map[string]bool{"cd": true, "chdir": true, "pushd": true, "popd": true, "source": true, ".": true, "eval": true}

// inShellWrappers run their inner command in the current shell, so a cd
// behind them still moves the shell.
var inShellWrappers = map[string]bool{"command": true, "builtin": true, "time": true}
