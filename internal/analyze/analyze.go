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
func (a *Analyzer) Analyze(c *ir.Command) {
	a.analyzeNode(c, c.Context)
}

func (a *Analyzer) analyzeNode(c *ir.Command, ctx ir.Context) {
	if c == nil {
		return
	}
	// Inherit / merge context from parent.
	c.Context = mergeContext(c.Context, ctx)

	if c.Kind == ir.KindSimple && c.Simple != nil {
		a.analyzeSimple(c)
	}

	for _, child := range c.Children {
		a.analyzeNode(child, c.Context)
	}
	if c.Simple != nil && c.Simple.Wrapper != nil && c.Simple.Wrapper.InnerCommand != nil {
		a.analyzeNode(c.Simple.Wrapper.InnerCommand, c.Context)
	}
	a.applyCompoundRedirectOps(c)
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
	if parent.Background {
		out.Background = true
	}
	return out
}

func (a *Analyzer) analyzeSimple(c *ir.Command) {
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
