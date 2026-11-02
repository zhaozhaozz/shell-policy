// Package analyze enriches a parsed IR command tree by:
//
//  1. Parsing argv against per-command specs.
//  2. Detecting wrapper commands (sudo, env, bash -c, ssh, docker exec,
//     find -exec, xargs ...) and recursively parsing their inner command.
//  3. Producing ResourceOp entries for each simple command.
//  4. Normalizing path arguments via the paths.Resolver.
//
// All transformations write back into the existing IR tree; no separate
// IR is produced.
package analyze

import (
	"strings"

	"github.com/self/shell_permission/internal/argv"
	"github.com/self/shell_permission/internal/ir"
	"github.com/self/shell_permission/internal/parser"
	"github.com/self/shell_permission/internal/paths"
)

// Analyzer holds shared state required to enrich an IR tree.
type Analyzer struct {
	Resolver *paths.Resolver
}

// New returns a ready-to-use Analyzer.
func New(resolver *paths.Resolver) *Analyzer {
	if resolver == nil {
		resolver = &paths.Resolver{}
	}
	return &Analyzer{Resolver: resolver}
}

// Analyze walks the command tree and enriches every simple command in
// place. It is safe to call multiple times.
//
// The walk follows execution order and tracks the shell's working directory,
// so in `cd /etc && rm passwd` the path resolves to /etc/passwd rather than
// against the resolver's starting Cwd.
func (a *Analyzer) Analyze(c *ir.Command) {
	start := a.Resolver.Cwd
	defer func() { a.Resolver.Cwd = start }()
	in := unknownCwd
	if start != "" {
		in = knownCwd(start)
	}
	a.analyzeNode(c, c.Context, in)
}

// setCwd points the resolver at the directory a command runs in.
func (a *Analyzer) setCwd(s cwdState) {
	if s.known {
		a.Resolver.Cwd = s.dir
	} else {
		a.Resolver.Cwd = ""
	}
}

// analyzeNode enriches c, which starts running in directory in, and returns
// the directory the shell is in afterwards.
func (a *Analyzer) analyzeNode(c *ir.Command, ctx ir.Context, in cwdState) cwdFlow {
	if c == nil {
		return unchanged(in)
	}
	// A statement ending in `&` runs in a background subshell: its cd never
	// reaches the next statement.
	background := c.Context.Background && !ctx.Background
	// Inherit / merge context from parent.
	c.Context = mergeContext(c.Context, ctx)

	var out cwdFlow
	switch c.Kind {
	case ir.KindSimple:
		out = a.analyzeSimpleNode(c, in)
	case ir.KindAnd:
		left := a.analyzeNode(child(c, 0), c.Context, in)
		right := a.analyzeNode(child(c, 1), c.Context, left.succ)
		out = cwdFlow{succ: right.succ, fail: left.fail.merge(right.fail)}
	case ir.KindOr:
		// The right side only runs when the left side failed.
		left := a.analyzeNode(child(c, 0), c.Context, in)
		right := a.analyzeNode(child(c, 1), c.Context, left.fail)
		out = cwdFlow{succ: left.succ.merge(right.succ), fail: right.fail}
	case ir.KindSequence:
		out = unchanged(in)
		for _, ch := range c.Children {
			out = a.analyzeNode(ch, c.Context, out.any())
		}
	case ir.KindPipeline:
		// Every element runs in a subshell (bash). zsh runs the last one in
		// the current shell, so a cd there leaves the directory unknown.
		var last cwdFlow
		for _, ch := range c.Children {
			last = a.analyzeNode(ch, c.Context, in)
		}
		out = unchanged(in)
		if len(c.Children) > 0 && last.any() != in {
			out = cwdFlow{}
		}
	case ir.KindSubshell, ir.KindCommandSubstitution, ir.KindProcessSubstitution:
		for _, ch := range c.Children {
			a.analyzeNode(ch, c.Context, in)
		}
		out = unchanged(in)
	case ir.KindFunction:
		// The body runs whenever the function is called, from any directory,
		// and the call may change the directory.
		for _, ch := range c.Children {
			a.analyzeNode(ch, c.Context, unknownCwd)
		}
		out = cwdFlow{}
	default:
		// Control flow: children are the nested statements in source order.
		// A loop body may run again after its own cd, so any directory change
		// inside makes the whole construct (and what follows) unknown.
		state := in
		if changesCwd(c) {
			state = unknownCwd
		}
		for _, ch := range c.Children {
			a.analyzeNode(ch, c.Context, state)
		}
		out = unchanged(state)
	}

	// Redirects on a compound command are opened before it runs.
	a.setCwd(in)
	a.applyCompoundRedirectOps(c)
	if background {
		return unchanged(in)
	}
	return out
}

func child(c *ir.Command, i int) *ir.Command {
	if i < len(c.Children) {
		return c.Children[i]
	}
	return nil
}

// analyzeSimpleNode analyzes one simple command, its substitutions and its
// wrapped inner command.
func (a *Analyzer) analyzeSimpleNode(c *ir.Command, in cwdState) cwdFlow {
	a.setCwd(in)
	if c.Simple != nil {
		a.analyzeSimple(c)
	}
	// Command and process substitutions run in subshells.
	for _, ch := range c.Children {
		a.analyzeNode(ch, c.Context, in)
	}
	w := c.Simple.Wrapper
	if w == nil {
		return a.cwdEffect(c, in)
	}
	if w.InnerCommand == nil {
		return unchanged(in)
	}
	innerIn := in
	switch {
	case w.Dir != "":
		innerIn = a.resolveDir(in, ir.ArgValue{Raw: w.Dir, Value: w.Dir, Confidence: ir.ConfStatic})
	case w.DirDynamic, w.Host != "" || w.Container != "" || w.Image != "":
		// Remote hosts and containers have their own filesystem.
		innerIn = unknownCwd
	}
	inner := a.analyzeNode(w.InnerCommand, c.Context, innerIn)
	if w.Type == "transparent" && inShellWrappers[w.Outer] || w.Type == "eval" {
		return inner
	}
	// Separate processes (sudo, env, bash -c, find -exec, ...) cannot move
	// this shell.
	return unchanged(in)
}

// mergeContext keeps the more permissive (more specific) flags set.
func mergeContext(child, parent ir.Context) ir.Context {
	out := child
	if parent.Depth > out.Depth {
		out.Depth = parent.Depth
	}
	if parent.InPipeline {
		out.InPipeline = true
	}
	if parent.InSubshell {
		out.InSubshell = true
	}
	if parent.InCommandSubstitution {
		out.InCommandSubstitution = true
	}
	if parent.InProcessSubstitution {
		out.InProcessSubstitution = true
	}
	if parent.InRemoteCommand {
		out.InRemoteCommand = true
		if out.RemoteHost == "" {
			out.RemoteHost = parent.RemoteHost
		}
	}
	if parent.InContainerCommand {
		out.InContainerCommand = true
		if out.ContainerName == "" {
			out.ContainerName = parent.ContainerName
		}
		if out.ContainerImage == "" {
			out.ContainerImage = parent.ContainerImage
		}
	}
	if parent.PrivilegeEscalated {
		out.PrivilegeEscalated = true
	}
	if parent.InFunction {
		out.InFunction = true
	}
	if parent.Background {
		out.Background = true
	}
	return out
}

func (a *Analyzer) analyzeSimple(c *ir.Command) {
	a.analyzeProgram(c)
	// `PATH=... cmd` or a bare `PATH=...` changes what runs.
	c.Simple.Operations = append(c.Simple.Operations, assignmentOps(c)...)
}

func (a *Analyzer) analyzeProgram(c *ir.Command) {
	sc := c.Simple
	if sc.Program.Value == "" {
		sc.NormalizedProgram = ""
		return
	}
	prog := sc.Program.Value
	sc.NormalizedProgram = prog

	// Wrapper detection happens first because wrappers reshape the
	// effective command (e.g. `sudo rm -rf /` ⇒ `rm -rf /` with
	// privilege escalation).
	if w := a.detectWrapper(c); w != nil {
		sc.Wrapper = w
		// Inner command (when known) gets recursively analyzed during
		// the descent in analyzeNode → analyzeNode for InnerCommand.
		// Wrappers usually do not produce direct resource ops other
		// than process_exec / remote_exec — record those.
		switch w.Type {
		case "ssh":
			sc.Operations = append(sc.Operations, ir.ResourceOp{
				Type:       ir.OpRemoteExec,
				Target:     w.Host,
				Confidence: confOf(sc),
				Context:    c.Context,
			})
		case "docker_exec", "kubectl_exec":
			sc.Operations = append(sc.Operations, ir.ResourceOp{
				Type:       ir.OpContainerWrite,
				Target:     w.Container,
				Confidence: confOf(sc),
				Context:    c.Context,
			})
		case "docker_run":
			sc.Operations = append(sc.Operations, ir.ResourceOp{
				Type:       ir.OpContainerWrite,
				Target:     w.Image,
				Confidence: confOf(sc),
				Context:    c.Context,
			})
		}
		a.applyRedirectOps(c)
		return
	}

	spec, ok := registry[prog]
	if !ok {
		// Unknown commands still get redirect-based operations recorded.
		a.applyRedirectOps(c)
		sc.Operations = append(sc.Operations, ir.ResourceOp{
			Type:       ir.OpUnknown,
			Subcommand: []string{prog},
			Confidence: confOf(sc),
			Dynamic:    sc.HasDynamicArgs,
			Context:    c.Context,
		})
		return
	}
	parsed := argv.Parse(sc.Argv, spec.Argv)
	sc.Flags = parsed.Flags
	sc.HasDynamicArgs = parsed.HasDynamic
	if spec.Subcommand != nil {
		sc.Subcommand = spec.Subcommand(parsed)
	}
	if spec.Operations != nil {
		ops := spec.Operations(c, parsed, a.Resolver)
		sc.Operations = append(sc.Operations, ops...)
	}
	a.applyRedirectOps(c)
}

func confOf(sc *ir.SimpleCommand) ir.Confidence {
	if sc.HasDynamicArgs {
		return ir.ConfPartiallyStatic
	}
	return ir.ConfStatic
}

// applyRedirectOps converts a command's Redirects into file_read /
// file_write / file_append operations.
func (a *Analyzer) applyRedirectOps(c *ir.Command) {
	if c.Simple == nil {
		return
	}
	a.appendRedirectOps(c.Simple, c.Redirects, c.Context)
}

func (a *Analyzer) applyCompoundRedirectOps(c *ir.Command) {
	if c == nil || c.Kind == ir.KindSimple || len(c.Redirects) == 0 {
		return
	}
	sink := firstSimpleLeaf(c)
	if sink == nil || sink.Simple == nil {
		return
	}
	a.appendRedirectOps(sink.Simple, c.Redirects, sink.Context)
}

func firstSimpleLeaf(c *ir.Command) *ir.Command {
	if c == nil {
		return nil
	}
	if c.Kind == ir.KindSimple && c.Simple != nil {
		return c
	}
	for _, child := range c.Children {
		if leaf := firstSimpleLeaf(child); leaf != nil {
			return leaf
		}
	}
	if c.Simple != nil && c.Simple.Wrapper != nil && c.Simple.Wrapper.InnerCommand != nil {
		return firstSimpleLeaf(c.Simple.Wrapper.InnerCommand)
	}
	return nil
}

func (a *Analyzer) appendRedirectOps(sc *ir.SimpleCommand, redirects []ir.Redirect, ctx ir.Context) {
	for _, r := range redirects {
		if isStreamDevice(r.Target) {
			continue
		}
		switch r.Op {
		case ir.RedirIn, ir.RedirHeredoc:
			sc.Operations = append(sc.Operations, ir.ResourceOp{
				Type:       ir.OpFileRead,
				Paths:      []ir.NormalizedPath{a.Resolver.Resolve(r.Target)},
				Confidence: r.Target.Confidence,
				Dynamic:    r.Target.Confidence != ir.ConfStatic,
				Context:    ctx,
			})
		case ir.RedirDupOut:
			// `>& file` is bash shorthand for `&> file`; only `>&2`, `>&-`
			// and `>&3-` duplicate or close a descriptor.
			if isFDTarget(r.Target) {
				continue
			}
			sc.Operations = append(sc.Operations, ir.ResourceOp{
				Type:       ir.OpFileWrite,
				Paths:      []ir.NormalizedPath{a.Resolver.Resolve(r.Target)},
				Confidence: r.Target.Confidence,
				Dynamic:    r.Target.Confidence != ir.ConfStatic,
				Context:    ctx,
			})
		case ir.RedirOut, ir.RedirClobber, ir.RedirReadWrite:
			sc.Operations = append(sc.Operations, ir.ResourceOp{
				Type:       ir.OpFileWrite,
				Paths:      []ir.NormalizedPath{a.Resolver.Resolve(r.Target)},
				Confidence: r.Target.Confidence,
				Dynamic:    r.Target.Confidence != ir.ConfStatic,
				Context:    ctx,
			})
		case ir.RedirAppend:
			sc.Operations = append(sc.Operations, ir.ResourceOp{
				Type:       ir.OpFileAppend,
				Paths:      []ir.NormalizedPath{a.Resolver.Resolve(r.Target)},
				Confidence: r.Target.Confidence,
				Dynamic:    r.Target.Confidence != ir.ConfStatic,
				Context:    ctx,
			})
		}
	}
}

// isStreamDevice reports a redirect target that never touches the
// filesystem. Allow rules must cover every operation of a command, so
// recording `2>/dev/null` as a system-path write would turn every quiet
// readonly command into an approval.
func isStreamDevice(v ir.ArgValue) bool {
	if v.Confidence != ir.ConfStatic {
		return false
	}
	switch v.Value {
	case "/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr":
		return true
	}
	return false
}

// isFDTarget reports a `>&` target that names a file descriptor (`2`, `-`,
// `3-`) rather than a file. Dynamic targets are treated as files.
func isFDTarget(v ir.ArgValue) bool {
	if v.Confidence != ir.ConfStatic {
		return false
	}
	s := strings.TrimSuffix(v.Value, "-")
	if s == "" {
		return v.Value == "-"
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// AnalyzeText is a convenience helper: parse + analyze.
func AnalyzeText(command string, resolver *paths.Resolver) (*parser.ParseResult, error) {
	pr, err := parser.Parse(command)
	if err != nil {
		return pr, err
	}
	a := New(resolver)
	if pr.Command != nil {
		a.Analyze(pr.Command)
	}
	return pr, nil
}

// staticArgs returns the static string values of argv positions starting
// at index i, omitting dynamic ones (callers usually want both lists).
func staticArgs(args []ir.ArgValue) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a.Confidence == ir.ConfStatic {
			out = append(out, a.Value)
		} else {
			out = append(out, "")
		}
	}
	return out
}

// joinArgvText joins ArgValue raw text with spaces. Used as a fallback
// when constructing inner command text.
func joinArgvText(args []ir.ArgValue) string {
	parts := make([]string, 0, len(args))
	for _, a := range args {
		raw := a.Raw
		if raw == "" {
			raw = a.Value
		}
		parts = append(parts, raw)
	}
	return strings.Join(parts, " ")
}

func joinArgvValues(args []ir.ArgValue) string {
	parts := make([]string, 0, len(args))
	for _, a := range args {
		if a.Value != "" {
			parts = append(parts, a.Value)
			continue
		}
		parts = append(parts, a.Raw)
	}
	return strings.Join(parts, " ")
}
