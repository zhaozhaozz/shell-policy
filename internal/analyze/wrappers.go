package analyze

import (
	"strings"

	"github.com/self/shell_permission/internal/ir"
	"github.com/self/shell_permission/internal/parser"
)

// detectWrapper checks whether the given simple command is a known
// wrapper (sudo, env, bash -c, ssh, docker exec, ...). When it is, the
// returned WrapperInfo will include a fully parsed InnerCommand whose
// context inherits the wrapper's policy-relevant flags (privilege,
// remote, container).
func (a *Analyzer) detectWrapper(c *ir.Command) *ir.WrapperInfo {
	sc := c.Simple
	if len(sc.Argv) == 0 || sc.Program.Confidence != ir.ConfStatic {
		return nil
	}
	prog := sc.Program.Value

	switch prog {
	case "sudo", "doas", "pkexec":
		return a.wrapSudo(c)
	case "su":
		return a.wrapSu(c)
	case "eval":
		return a.wrapEval(c)
	case "env":
		return a.wrapEnv(c)
	case "time", "command", "builtin", "exec", "nohup":
		return a.wrapTransparent(c, prog)
	case "bash", "sh", "zsh", "dash", "ash", "ksh":
		return a.wrapShellC(c, prog)
	case "ssh":
		return a.wrapSSH(c)
	case "docker", "podman":
		if w := a.wrapDocker(c); w != nil {
			return w
		}
	case "kubectl":
		return a.wrapKubectl(c)
	case "find":
		return a.wrapFindExec(c)
	case "xargs":
		return a.wrapXargs(c)
	case "python", "python3", "node", "ruby", "perl":
		return a.wrapLanguageEval(c, prog)
	}
	return nil
}

// extractStringFlag pulls a -X / --xxx / --xxx=value argument from the
// argv list (skipping argv[0]). It returns the flag's value, the
// remaining args (with the flag removed), and whether the flag was
// found. Only static argv values are inspected.
func extractStringFlag(args []ir.ArgValue, names ...string) (val string, rest []ir.ArgValue, ok bool) {
	rest = make([]ir.ArgValue, 0, len(args))
	skipNext := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if skipNext {
			val = a.Value
			ok = true
			skipNext = false
			continue
		}
		if a.Confidence != ir.ConfStatic {
			rest = append(rest, a)
			continue
		}
		matched := false
		for _, n := range names {
			if a.Value == n {
				skipNext = true
				matched = true
				break
			}
			if isShortFlag(n) && strings.HasPrefix(a.Value, n) && a.Value != n {
				val = a.Value[len(n):]
				ok = true
				matched = true
				break
			}
			if strings.HasPrefix(a.Value, n+"=") {
				val = a.Value[len(n)+1:]
				ok = true
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		rest = append(rest, a)
	}
	return val, rest, ok
}

// extractBoolFlag removes flag occurrences and reports whether any was found.
func extractBoolFlag(args []ir.ArgValue, names ...string) (bool, []ir.ArgValue) {
	rest := make([]ir.ArgValue, 0, len(args))
	found := false
	for _, a := range args {
		if a.Confidence == ir.ConfStatic {
			matched := false
			for _, n := range names {
				if a.Value == n || containsShortBoolFlag(a.Value, n) {
					found = true
					matched = true
					break
				}
			}
			if matched {
				continue
			}
		}
		rest = append(rest, a)
	}
	return found, rest
}

func (a *Analyzer) parseInner(text string, ctx ir.Context) *ir.Command {
	if text == "" {
		return nil
	}
	pr, err := parser.Parse(text)
	if err != nil || pr.Command == nil {
		return &ir.Command{
			Kind:      ir.KindControlFlow,
			Source:    ir.SourceSpan{Text: text},
			Context:   ctx,
			RiskHints: []string{"inner_parse_error"},
		}
	}
	pr.Command.Context = mergeContext(pr.Command.Context, ctx)
	return pr.Command
}

// --- Specific wrappers ----------------------------------------------------

// sudoValueFlags consume the next word (or an attached value).
var sudoValueFlags = map[string]bool{
	"-u": true, "--user": true, "-g": true, "--group": true, "-h": true, "--host": true,
	"-p": true, "--prompt": true, "-C": true, "--close-from": true, "-D": true, "--chdir": true,
	"-r": true, "--role": true, "-t": true, "--type": true, "-U": true, "--other-user": true,
	"-T": true, "--command-timeout": true, "-R": true, "--chroot": true,
}

// wrapSudo handles sudo and the sudo-like doas and pkexec: options, then the
// command to run with elevated privileges.
func (a *Analyzer) wrapSudo(c *ir.Command) *ir.WrapperInfo {
	args := c.Simple.Argv[1:]
	prog := c.Simple.Program.Value
	w := &ir.WrapperInfo{Type: "sudo", Outer: prog, Privilege: true}
	// Consume sudo's own options; the first non-option word starts the
	// command. Unknown options are skipped as boolean flags so that
	// `sudo -n rm ...` still exposes `rm`.
	for len(args) > 0 {
		a0 := args[0]
		if a0.Confidence != ir.ConfStatic || !strings.HasPrefix(a0.Value, "-") || a0.Value == "-" {
			break
		}
		if a0.Value == "--" {
			args = args[1:]
			break
		}
		name, val, hasVal := a0.Value, "", false
		if i := strings.Index(name, "="); strings.HasPrefix(name, "--") && i > 0 {
			name, val, hasVal = name[:i], name[i+1:], true
		} else if !strings.HasPrefix(name, "--") && len(name) > 2 && sudoValueFlags[name[:2]] {
			name, val, hasVal = name[:2], name[2:], true
		}
		args = args[1:]
		if !sudoValueFlags[name] {
			continue
		}
		dynamic := false
		if !hasVal && len(args) > 0 {
			val, dynamic = args[0].Value, args[0].Confidence != ir.ConfStatic
			args = args[1:]
		}
		switch name {
		case "-u", "--user":
			w.User = val
		case "-D", "--chdir", "-R", "--chroot":
			// The command starts in another directory (or root).
			if dynamic || name == "-R" || name == "--chroot" {
				w.DirDynamic = true
			} else {
				w.Dir = val
			}
		}
	}
	if len(args) == 0 {
		return w
	}
	innerText := joinArgvText(args)
	innerCtx := c.Context
	innerCtx.PrivilegeEscalated = true
	w.InnerText = innerText
	w.InnerCommand = a.parseInner(innerText, innerCtx)
	return w
}

// wrapSu exposes the command of `su -c 'cmd' [user]`; a bare su opens a
// privileged shell and stays a leaf.
func (a *Analyzer) wrapSu(c *ir.Command) *ir.WrapperInfo {
	cmd, _, ok := extractStringFlag(c.Simple.Argv[1:], "-c", "--command")
	w := &ir.WrapperInfo{Type: "sudo", Outer: "su", Privilege: true}
	if !ok {
		return w
	}
	innerCtx := c.Context
	innerCtx.PrivilegeEscalated = true
	w.InnerText = cmd
	w.InnerCommand = a.parseInner(cmd, innerCtx)
	return w
}

// wrapEval parses the text of `eval` with static arguments as a command run
// in the current shell. A dynamic eval stays an unknown command.
func (a *Analyzer) wrapEval(c *ir.Command) *ir.WrapperInfo {
	args := c.Simple.Argv[1:]
	if len(args) == 0 {
		return nil
	}
	for _, x := range args {
		if x.Confidence != ir.ConfStatic {
			return nil
		}
	}
	// eval joins its arguments with spaces and parses the result.
	text := joinArgvValues(args)
	return &ir.WrapperInfo{Type: "eval", Outer: "eval", InnerText: text, InnerCommand: a.parseInner(text, c.Context)}
}

func consumeLeadingStringFlag(args []ir.ArgValue, names ...string) ([]ir.ArgValue, bool) {
	if len(args) == 0 || args[0].Confidence != ir.ConfStatic {
		return args, false
	}
	value := args[0].Value
	for _, name := range names {
		if value == name {
			if len(args) >= 2 {
				return args[2:], true
			}
			return args[1:], true
		}
		if strings.HasPrefix(value, name+"=") || (isShortFlag(name) && strings.HasPrefix(value, name) && value != name) {
			return args[1:], true
		}
	}
	return args, false
}

func consumeLeadingBoolFlag(args []ir.ArgValue, names ...string) ([]ir.ArgValue, bool) {
	if len(args) == 0 || args[0].Confidence != ir.ConfStatic {
		return args, false
	}
	value := args[0].Value
	for _, name := range names {
		if value == name || containsShortBoolFlag(value, name) {
			return args[1:], true
		}
	}
	return args, false
}

func isShortFlag(name string) bool {
	return len(name) == 2 && strings.HasPrefix(name, "-") && !strings.HasPrefix(name, "--")
}

func containsShortBoolFlag(value, name string) bool {
	if !isShortFlag(name) || !strings.HasPrefix(value, "-") || strings.HasPrefix(value, "--") || value == "-" {
		return false
	}
	return strings.Contains(value[1:], name[1:])
}

func (a *Analyzer) wrapEnv(c *ir.Command) *ir.WrapperInfo {
	args := c.Simple.Argv[1:]
	env := map[string]string{}
	chdir, chdirDynamic := "", false
	for len(args) > 0 {
		a0 := args[0]
		if a0.Confidence != ir.ConfStatic {
			break
		}
		// Skip env flags that consume a value.
		if a0.Value == "-i" || a0.Value == "--ignore-environment" {
			args = args[1:]
			continue
		}
		if a0.Value == "-u" || a0.Value == "--unset" {
			if len(args) >= 2 {
				args = args[2:]
				continue
			}
		}
		// env -C dir / --chdir=dir runs the command in another directory.
		if a0.Value == "-C" || a0.Value == "--chdir" {
			if len(args) >= 2 {
				if args[1].Confidence == ir.ConfStatic {
					chdir = args[1].Value
				} else {
					chdirDynamic = true
				}
				args = args[2:]
				continue
			}
		}
		if v, ok := strings.CutPrefix(a0.Value, "--chdir="); ok {
			chdir = v
			args = args[1:]
			continue
		}
		if strings.HasPrefix(a0.Value, "-") {
			break
		}
		if eq := strings.Index(a0.Value, "="); eq > 0 {
			env[a0.Value[:eq]] = a0.Value[eq+1:]
			args = args[1:]
			continue
		}
		break
	}
	if len(args) == 0 {
		return &ir.WrapperInfo{Type: "env", Outer: "env", Env: env}
	}
	innerText := joinArgvText(args)
	inner := a.parseInner(innerText, c.Context)
	return &ir.WrapperInfo{
		Type:         "env",
		Outer:        "env",
		Env:          env,
		InnerText:    innerText,
		InnerCommand: inner,
		Dir:          chdir,
		DirDynamic:   chdirDynamic,
	}
}

func (a *Analyzer) wrapTransparent(c *ir.Command, prog string) *ir.WrapperInfo {
	args := c.Simple.Argv[1:]
	if len(args) == 0 {
		return nil
	}
	innerText := joinArgvText(args)
	inner := a.parseInner(innerText, c.Context)
	return &ir.WrapperInfo{
		Type:         "transparent",
		Outer:        prog,
		InnerText:    innerText,
		InnerCommand: inner,
	}
}

func (a *Analyzer) wrapShellC(c *ir.Command, prog string) *ir.WrapperInfo {
	args := c.Simple.Argv[1:]
	cVal, rest, ok := extractStringFlag(args, "-c")
	if !ok {
		return nil
	}
	_ = rest
	innerCtx := c.Context
	inner := a.parseInner(cVal, innerCtx)
	wType := "shell_c"
	return &ir.WrapperInfo{
		Type:         wType,
		Outer:        prog,
		InnerText:    cVal,
		InnerCommand: inner,
	}
}

func (a *Analyzer) wrapSSH(c *ir.Command) *ir.WrapperInfo {
	args := c.Simple.Argv[1:]
	// Strip well-known value flags.
	stripValue := []string{"-i", "-p", "-l", "-o", "-F", "-J", "-W", "-D", "-L", "-R", "-b", "-c", "-e", "-I", "-m", "-O", "-Q", "-S", "-w"}
	for {
		changed := false
		for _, f := range stripValue {
			_, rest, ok := extractStringFlag(args, f)
			if ok {
				args = rest
				changed = true
				break
			}
		}
		if !changed {
			break
		}
	}
	// Strip well-known boolean flags.
	boolFlags := []string{"-4", "-6", "-A", "-a", "-C", "-f", "-G", "-g", "-K", "-k", "-M", "-N", "-n", "-q", "-s", "-T", "-t", "-V", "-v", "-X", "-x", "-Y", "-y"}
	for _, f := range boolFlags {
		_, args = extractBoolFlag(args, f)
	}
	if len(args) == 0 {
		return &ir.WrapperInfo{Type: "ssh", Outer: "ssh"}
	}
	host := args[0].Value
	user := ""
	if at := strings.Index(host, "@"); at >= 0 {
		user = host[:at]
		host = host[at+1:]
	}
	rest := args[1:]
	if len(rest) == 0 {
		return &ir.WrapperInfo{Type: "ssh", Outer: "ssh", Host: host, User: user}
	}
	innerText := joinArgvValues(rest)
	innerCtx := c.Context
	innerCtx.InRemoteCommand = true
	innerCtx.RemoteHost = host
	inner := a.parseInner(innerText, innerCtx)
	return &ir.WrapperInfo{
		Type:         "ssh",
		Outer:        "ssh",
		Host:         host,
		User:         user,
		InnerText:    innerText,
		InnerCommand: inner,
	}
}

func (a *Analyzer) wrapDocker(c *ir.Command) *ir.WrapperInfo {
	args := c.Simple.Argv[1:]
	if len(args) == 0 || args[0].Confidence != ir.ConfStatic {
		return nil
	}
	switch args[0].Value {
	case "exec":
		return a.wrapDockerExec(c, args[1:])
	case "run":
		return a.wrapDockerRun(c, args[1:])
	}
	return nil
}

func (a *Analyzer) wrapDockerExec(c *ir.Command, args []ir.ArgValue) *ir.WrapperInfo {
	// Strip docker exec value flags.
	for _, f := range []string{"-u", "--user", "-w", "--workdir", "-e", "--env"} {
		for {
			_, rest, ok := extractStringFlag(args, f)
			if !ok {
				break
			}
			args = rest
		}
	}
	for _, f := range []string{"-i", "--interactive", "-t", "--tty", "-d", "--detach", "--privileged"} {
		_, args = extractBoolFlag(args, f)
	}
	if len(args) == 0 {
		return &ir.WrapperInfo{Type: "docker_exec", Outer: "docker exec"}
	}
	container := args[0].Value
	rest := args[1:]
	if len(rest) == 0 {
		return &ir.WrapperInfo{Type: "docker_exec", Outer: "docker exec", Container: container}
	}
	innerText := joinArgvText(rest)
	innerCtx := c.Context
	innerCtx.InContainerCommand = true
	innerCtx.ContainerName = container
	inner := a.parseInner(innerText, innerCtx)
	return &ir.WrapperInfo{
		Type:         "docker_exec",
		Outer:        "docker exec",
		Container:    container,
		InnerText:    innerText,
		InnerCommand: inner,
	}
}

func (a *Analyzer) wrapDockerRun(c *ir.Command, args []ir.ArgValue) *ir.WrapperInfo {
	w := &ir.WrapperInfo{Type: "docker_run", Outer: "docker run"}
	// Strip a small set of docker run flags we care about.
	for {
		changed := false
		for _, f := range []string{"-v", "--volume", "--mount", "-e", "--env", "-p", "--publish", "--name", "--network", "-w", "--workdir", "--entrypoint"} {
			val, rest, ok := extractStringFlag(args, f)
			if ok {
				args = rest
				changed = true
				if f == "--network" {
					if w.Env == nil {
						w.Env = map[string]string{}
					}
					w.Env["__network"] = val
				}
				if f == "-v" || f == "--volume" || f == "--mount" {
					if w.Env == nil {
						w.Env = map[string]string{}
					}
					w.Env["__mount"] = val
				}
				break
			}
		}
		if !changed {
			break
		}
	}
	for _, f := range []string{"-i", "--interactive", "-t", "--tty", "-d", "--detach", "--rm", "--privileged"} {
		matched, rest := extractBoolFlag(args, f)
		args = rest
		if f == "--privileged" && matched {
			w.Privilege = true
		}
	}
	if len(args) == 0 {
		return w
	}
	w.Image = args[0].Value
	rest := args[1:]
	if len(rest) > 0 {
		innerText := joinArgvText(rest)
		innerCtx := c.Context
		innerCtx.InContainerCommand = true
		innerCtx.ContainerImage = w.Image
		w.InnerText = innerText
		w.InnerCommand = a.parseInner(innerText, innerCtx)
	}
	return w
}

func (a *Analyzer) wrapKubectl(c *ir.Command) *ir.WrapperInfo {
	args := c.Simple.Argv[1:]
	if len(args) == 0 || args[0].Confidence != ir.ConfStatic || args[0].Value != "exec" {
		return nil
	}
	args = args[1:]
	for len(args) > 0 {
		if rest, ok := consumeLeadingStringFlag(args, "-n", "--namespace", "-c", "--container"); ok {
			args = rest
			continue
		}
		if rest, ok := consumeLeadingBoolFlag(args, "-i", "--stdin", "-t", "--tty"); ok {
			args = rest
			continue
		}
		break
	}
	if len(args) == 0 {
		return &ir.WrapperInfo{Type: "kubectl_exec", Outer: "kubectl exec"}
	}
	pod := args[0].Value
	rest := args[1:]
	// Drop leading `--` separator if present.
	if len(rest) > 0 && rest[0].Value == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return &ir.WrapperInfo{Type: "kubectl_exec", Outer: "kubectl exec", Container: pod}
	}
	innerText := joinArgvText(rest)
	innerCtx := c.Context
	innerCtx.InContainerCommand = true
	innerCtx.ContainerName = pod
	return &ir.WrapperInfo{
		Type:         "kubectl_exec",
		Outer:        "kubectl exec",
		Container:    pod,
		InnerText:    innerText,
		InnerCommand: a.parseInner(innerText, innerCtx),
	}
}

func (a *Analyzer) wrapFindExec(c *ir.Command) *ir.WrapperInfo {
	args := c.Simple.Argv[1:]
	roots := findSearchRoots(args)
	// Find -exec / -execdir consumes args until ';' or '+'.
	for i := 0; i < len(args); i++ {
		v := args[i].Value
		if args[i].Confidence != ir.ConfStatic {
			continue
		}
		if v == "-exec" || v == "-execdir" {
			cmdArgs := []ir.ArgValue{}
			for j := i + 1; j < len(args); j++ {
				if args[j].Confidence == ir.ConfStatic && (args[j].Value == ";" || args[j].Value == "+") {
					break
				}
				// {} stands for the matched files, which lie under the
				// search roots: analyze it as "<root>/*" for each root.
				if args[j].Confidence == ir.ConfStatic && args[j].Value == "{}" {
					for _, root := range roots {
						cmdArgs = append(cmdArgs, ir.ArgValue{Raw: rawText(root) + "/*", Value: root.Value + "/*", Confidence: root.Confidence})
					}
					continue
				}
				cmdArgs = append(cmdArgs, args[j])
			}
			if len(cmdArgs) == 0 {
				continue
			}
			innerText := joinArgvText(cmdArgs)
			inner := a.parseInner(innerText, c.Context)
			markDynamicWords(inner, "{}")
			return &ir.WrapperInfo{
				Type:         "find_exec",
				Outer:        "find " + v,
				InnerText:    innerText,
				InnerCommand: inner,
				// -execdir runs in each match's directory.
				DirDynamic: v == "-execdir",
			}
		}
		if v == "-delete" {
			innerText := "rm " + joinArgvText(roots)
			return &ir.WrapperInfo{
				Type:         "find_delete",
				Outer:        "find -delete",
				InnerText:    innerText,
				InnerCommand: a.parseInner(innerText, c.Context),
			}
		}
	}
	return nil
}

func findSearchRoots(args []ir.ArgValue) []ir.ArgValue {
	roots := []ir.ArgValue{}
	for _, a := range args {
		if a.Confidence == ir.ConfStatic {
			if strings.HasPrefix(a.Value, "-") || a.Value == "(" || a.Value == "!" {
				break
			}
		}
		roots = append(roots, a)
	}
	if len(roots) == 0 {
		return []ir.ArgValue{{Raw: ".", Value: ".", Confidence: ir.ConfStatic}}
	}
	return roots
}

func (a *Analyzer) wrapXargs(c *ir.Command) *ir.WrapperInfo {
	args, replace := xargsCommand(c.Simple.Argv[1:])
	if len(args) == 0 {
		// xargs with no command defaults to /bin/echo, which is harmless.
		return &ir.WrapperInfo{Type: "xargs", Outer: "xargs"}
	}
	innerText := joinArgvText(args)
	inner := a.parseInner(innerText, c.Context)
	// Arguments read from stdin are unknown: either the words carrying the
	// -I replacement string, or extra arguments appended to the command.
	if replace != "" {
		markDynamicWords(inner, replace)
	} else if inner != nil && inner.Kind == ir.KindSimple && inner.Simple != nil {
		inner.Simple.Argv = append(inner.Simple.Argv, ir.ArgValue{Raw: "<stdin>", Confidence: ir.ConfDynamic})
	}
	return &ir.WrapperInfo{
		Type:         "xargs",
		Outer:        "xargs",
		InnerText:    innerText,
		InnerCommand: inner,
	}
}

func (a *Analyzer) wrapLanguageEval(c *ir.Command, prog string) *ir.WrapperInfo {
	args := c.Simple.Argv[1:]
	flag := "-c"
	if prog == "node" {
		flag = "-e"
	} else if prog == "perl" || prog == "ruby" {
		flag = "-e"
	}
	val, _, ok := extractStringFlag(args, flag)
	if !ok {
		return nil
	}
	return &ir.WrapperInfo{
		Type:      "language_eval",
		Outer:     prog,
		InnerText: val,
		// We deliberately do NOT recursively shell-parse language code:
		// it would be misleading. The presence of the wrapper alone is
		// the signal policy uses (template.inline-eval.ask-or-deny).
	}
}

func rawText(a ir.ArgValue) string {
	if a.Raw != "" {
		return a.Raw
	}
	return a.Value
}

// markDynamicWords marks argv words and redirect targets of an inner command
// that contain placeholder as dynamic: their value is only known at run time
// (xargs -I input, a find {} embedded in a longer word).
func markDynamicWords(c *ir.Command, placeholder string) {
	mark := func(v *ir.ArgValue) {
		if strings.Contains(v.Value, placeholder) || strings.Contains(v.Raw, placeholder) {
			v.Confidence = ir.ConfDynamic
			v.Value = ""
		}
	}
	ir.Walk(c, func(n *ir.Command) {
		if n.Simple != nil {
			for i := range n.Simple.Argv {
				mark(&n.Simple.Argv[i])
			}
			if len(n.Simple.Argv) > 0 {
				n.Simple.Program = n.Simple.Argv[0]
			}
		}
		for i := range n.Redirects {
			mark(&n.Redirects[i].Target)
		}
	})
}

// xargsValueFlags take the next word (or an attached value) as their value.
var xargsValueFlags = map[string]bool{"-I": true, "-n": true, "-P": true, "-d": true, "-E": true, "-L": true, "-s": true, "-a": true}

// xargsCommand skips xargs's own leading options and returns the command
// words plus the -I/-i replacement string ("" when not replacing).
func xargsCommand(args []ir.ArgValue) ([]ir.ArgValue, string) {
	replace := ""
	for len(args) > 0 {
		x := args[0]
		if x.Confidence != ir.ConfStatic || !strings.HasPrefix(x.Value, "-") || x.Value == "-" {
			break
		}
		args = args[1:]
		v := x.Value
		switch {
		case v == "--":
			return args, replace
		case strings.HasPrefix(v, "--"):
			// --replace[=R] and the other long options carry values inline.
			if r, ok := strings.CutPrefix(v, "--replace"); ok && (r == "" || r[0] == '=') {
				replace = strings.TrimPrefix(r, "=")
				if replace == "" {
					replace = "{}"
				}
			}
		case strings.HasPrefix(v, "-i"):
			replace = v[2:] // optional attached value
			if replace == "" {
				replace = "{}"
			}
		case xargsValueFlags[v[:2]]:
			val := v[2:]
			if val == "" && len(args) > 0 {
				val = args[0].Value
				args = args[1:]
			}
			if v[:2] == "-I" {
				replace = val
			}
		}
		// Other short options (-r, -0, -t, -p, -x, -e[E], -l[N]) are flags
		// or carry attached values only.
	}
	return args, replace
}
