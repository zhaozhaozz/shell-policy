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
	case "sudo":
		return a.wrapSudo(c)
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
				if a.Value == n {
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

func (a *Analyzer) wrapSudo(c *ir.Command) *ir.WrapperInfo {
	args := c.Simple.Argv[1:]
	user := ""
	preserve := false
	// Handle a small subset of sudo flags that consume a value.
	for {
		if len(args) == 0 {
			break
		}
		a0 := args[0]
		if a0.Confidence != ir.ConfStatic || !strings.HasPrefix(a0.Value, "-") {
			break
		}
		switch a0.Value {
		case "-u", "--user":
			if len(args) >= 2 {
				user = args[1].Value
				args = args[2:]
				continue
			}
		case "-E", "--preserve-env":
			preserve = true
			args = args[1:]
			continue
		case "-i", "-s":
			args = args[1:]
			continue
		case "--":
			args = args[1:]
			break
		}
		// Unknown sudo flag — stop consuming so we don't accidentally drop
		// a positional that begins with `-`.
		break
	}
	_ = preserve
	if len(args) == 0 {
		return &ir.WrapperInfo{Type: "sudo", Outer: "sudo", Privilege: true, User: user}
	}
	innerText := joinArgvText(args)
	innerCtx := c.Context
	innerCtx.PrivilegeEscalated = true
	inner := a.parseInner(innerText, innerCtx)
	return &ir.WrapperInfo{
		Type:         "sudo",
		Outer:        "sudo",
		User:         user,
		Privilege:    true,
		InnerText:    innerText,
		InnerCommand: inner,
	}
}

func (a *Analyzer) wrapEnv(c *ir.Command) *ir.WrapperInfo {
	args := c.Simple.Argv[1:]
	env := map[string]string{}
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
	innerText := joinArgvText(rest)
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
	for _, f := range []string{"-n", "--namespace", "-c", "--container"} {
		for {
			_, rest, ok := extractStringFlag(args, f)
			if !ok {
				break
			}
			args = rest
		}
	}
	for _, f := range []string{"-i", "--stdin", "-t", "--tty"} {
		_, args = extractBoolFlag(args, f)
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
				cmdArgs = append(cmdArgs, args[j])
			}
			if len(cmdArgs) == 0 {
				continue
			}
			innerText := joinArgvText(cmdArgs)
			inner := a.parseInner(innerText, c.Context)
			return &ir.WrapperInfo{
				Type:         "find_exec",
				Outer:        "find -exec",
				InnerText:    innerText,
				InnerCommand: inner,
			}
		}
		if v == "-delete" {
			// `find -delete` is itself a delete operation. We expose this as
			// an inner op via a synthesized rm-equivalent simple command so
			// the policy chain sees a file_delete operation.
			return &ir.WrapperInfo{
				Type:      "find_delete",
				Outer:     "find -delete",
				InnerText: "rm",
			}
		}
	}
	return nil
}

func (a *Analyzer) wrapXargs(c *ir.Command) *ir.WrapperInfo {
	args := c.Simple.Argv[1:]
	// Strip xargs value flags.
	for _, f := range []string{"-I", "-n", "-P", "-d", "-E", "-L", "-s", "--max-args", "--max-procs", "--delimiter"} {
		for {
			_, rest, ok := extractStringFlag(args, f)
			if !ok {
				break
			}
			args = rest
		}
	}
	for _, f := range []string{"-r", "--no-run-if-empty", "-0", "--null", "-t", "--verbose", "-p"} {
		_, args = extractBoolFlag(args, f)
	}
	if len(args) == 0 {
		// xargs with no command defaults to /bin/echo, which is harmless.
		return &ir.WrapperInfo{Type: "xargs", Outer: "xargs"}
	}
	innerText := joinArgvText(args)
	inner := a.parseInner(innerText, c.Context)
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
