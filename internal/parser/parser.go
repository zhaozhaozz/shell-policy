// Package parser converts raw shell command text into the project IR.
//
// It uses mvdan.cc/sh/v3/syntax to obtain a Bash AST, then walks the AST
// and produces an ir.Command tree. The parser does not perform any
// expansion (no $VAR, no globbing, no command substitution evaluation):
// dynamic parts are flagged so that downstream policy can refuse to
// auto-allow them.
package parser

import (
	"fmt"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/zhaozhaozz/shell-policy/internal/ir"
)

// ParseError is a structured parse error.
type ParseError struct {
	Message string `json:"message"`
	Line    uint   `json:"line,omitempty"`
	Col     uint   `json:"col,omitempty"`
}

func (e ParseError) Error() string { return e.Message }

// ParseResult is what Parse returns.
type ParseResult struct {
	Raw     string       `json:"raw"`
	Shell   string       `json:"shell"`
	Command *ir.Command  `json:"command,omitempty"`
	Errors  []ParseError `json:"errors,omitempty"`
}

// Parse parses a Bash command into the IR. An empty result is still
// returned on parse error so the caller may inspect Errors.
func Parse(command string) (*ParseResult, error) {
	res := &ParseResult{Raw: command, Shell: "bash"}
	p := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := p.Parse(strings.NewReader(command), "")
	if err != nil {
		if pe, ok := err.(syntax.ParseError); ok {
			res.Errors = append(res.Errors, ParseError{
				Message: pe.Text,
				Line:    pe.Pos.Line(),
				Col:     pe.Pos.Col(),
			})
		} else {
			res.Errors = append(res.Errors, ParseError{Message: err.Error()})
		}
		return res, err
	}

	conv := &converter{src: command, idCounter: 0}
	root := conv.convertStmts(file.Stmts, ir.Context{Depth: 0})
	res.Command = root
	return res, nil
}

// converter holds state for one parse → IR conversion.
type converter struct {
	src       string
	idCounter int
}

func (c *converter) nextID(prefix string) string {
	c.idCounter++
	return fmt.Sprintf("%s_%d", prefix, c.idCounter)
}

// convertStmts builds a sequence node from a list of statements. If the
// list contains a single statement, that statement's node is returned
// directly to avoid unnecessary wrapping.
func (c *converter) convertStmts(stmts []*syntax.Stmt, ctx ir.Context) *ir.Command {
	if len(stmts) == 0 {
		return &ir.Command{ID: c.nextID("empty"), Kind: ir.KindSequence, Context: ctx}
	}
	if len(stmts) == 1 {
		return c.convertStmt(stmts[0], ctx)
	}
	seq := &ir.Command{
		ID:      c.nextID("seq"),
		Kind:    ir.KindSequence,
		Context: ctx,
	}
	for _, s := range stmts {
		seq.Children = append(seq.Children, c.convertStmt(s, ctx))
	}
	return seq
}

func (c *converter) convertStmt(s *syntax.Stmt, ctx ir.Context) *ir.Command {
	cmd := c.convertCommand(s.Cmd, s, ctx)
	// Apply redirects from the statement to the produced node.
	if len(s.Redirs) > 0 {
		cmd.Redirects = append(cmd.Redirects, c.convertRedirects(s.Redirs)...)
		// `> "$(cmd)"`: substitutions in redirect targets run first.
		var subs []*ir.Command
		for _, r := range s.Redirs {
			if r.Word != nil {
				subs = append(subs, c.substitutions(r.Word, ctx)...)
			}
		}
		if len(subs) > 0 {
			if cmd.Kind == ir.KindSimple {
				cmd.Children = append(cmd.Children, subs...)
			} else {
				cmd = &ir.Command{ID: c.nextID("seq"), Kind: ir.KindSequence, Children: append(subs, cmd), Context: ctx}
			}
		}
	}
	if s.Background {
		cmd.Context.Background = true
		// Wrap background statements in a node that explicitly says so for
		// downstream rules. We just set the context flag rather than wrap.
	}
	return cmd
}

func (c *converter) convertCommand(node syntax.Command, stmt *syntax.Stmt, ctx ir.Context) *ir.Command {
	switch v := node.(type) {
	case *syntax.CallExpr:
		return c.convertCall(v, stmt, ctx)

	case *syntax.BinaryCmd:
		return c.convertBinary(v, ctx)

	case *syntax.Block:
		return c.convertStmts(v.Stmts, ctx)

	case *syntax.Subshell:
		sctx := ctx
		sctx.Depth++
		sctx.InSubshell = true
		inner := c.convertStmts(v.Stmts, sctx)
		return &ir.Command{
			ID:       c.nextID("subshell"),
			Kind:     ir.KindSubshell,
			Children: []*ir.Command{inner},
			Source:   sourceSpan(stmt, c.src),
			Context:  ctx,
		}

	case *syntax.IfClause, *syntax.ForClause, *syntax.WhileClause, *syntax.CaseClause:
		// Walk all nested statements so we still discover risky inner
		// commands. We mark the wrapping node as control_flow.
		out := &ir.Command{
			ID:      c.nextID("control"),
			Kind:    ir.KindControlFlow,
			Source:  sourceSpan(stmt, c.src),
			Context: ctx,
		}
		// Recursively walk to find inner statements via syntax.Walk.
		syntax.Walk(node, func(n syntax.Node) bool {
			if s, ok := n.(*syntax.Stmt); ok && s != stmt {
				out.Children = append(out.Children, c.convertStmt(s, ctx))
				return false
			}
			return true
		})
		return out

	case *syntax.DeclClause:
		return c.convertDecl(v, stmt, ctx)

	case *syntax.TimeClause:
		// `time cmd` runs cmd in the current shell.
		if v.Stmt == nil {
			return c.builtinNode("time", v, stmt, ctx)
		}
		return c.convertStmt(v.Stmt, ctx)

	case *syntax.CoprocClause:
		// A coprocess runs asynchronously, like a background job.
		bctx := ctx
		bctx.Background = true
		return c.convertStmt(v.Stmt, bctx)

	case *syntax.TestClause:
		return c.builtinNode("[[", v, stmt, ctx)

	case *syntax.ArithmCmd:
		return c.builtinNode("((", v, stmt, ctx)

	case *syntax.LetClause:
		return c.builtinNode("let", v, stmt, ctx)

	case *syntax.FuncDecl:
		// The body is kept as children so its commands are evaluated too;
		// they run whenever the function is called.
		fctx := ctx
		fctx.InFunction = true
		out := &ir.Command{
			ID:        c.nextID("func"),
			Kind:      ir.KindFunction,
			Source:    sourceSpan(stmt, c.src),
			Context:   ctx,
			RiskHints: []string{"function_definition"},
		}
		if v.Body != nil {
			out.Children = []*ir.Command{c.convertStmt(v.Body, fctx)}
		}
		return out

	default:
		// Still surface nested statements so no command hides in a node
		// type the converter does not model.
		out := &ir.Command{
			ID:        c.nextID("unknown"),
			Kind:      ir.KindControlFlow,
			Source:    sourceSpan(stmt, c.src),
			Context:   ctx,
			RiskHints: []string{fmt.Sprintf("unhandled_node:%T", node)},
		}
		syntax.Walk(node, func(n syntax.Node) bool {
			if s, ok := n.(*syntax.Stmt); ok && s != stmt {
				out.Children = append(out.Children, c.convertStmt(s, ctx))
				return false
			}
			return true
		})
		return out
	}
}

// builtinNode models a shell keyword without file effects ([[ ]], (( )),
// let) as a simple command named prog; command substitutions inside it
// become children so they are still evaluated.
func (c *converter) builtinNode(prog string, node syntax.Node, stmt *syntax.Stmt, ctx ir.Context) *ir.Command {
	name := ir.ArgValue{Raw: prog, Value: prog, Confidence: ir.ConfStatic}
	return &ir.Command{
		ID:       c.nextID("simple"),
		Kind:     ir.KindSimple,
		Simple:   &ir.SimpleCommand{Program: name, Argv: []ir.ArgValue{name}},
		Children: c.substitutions(node, ctx),
		Source:   sourceSpan(stmt, c.src),
		Context:  ctx,
	}
}

// convertDecl turns `export|declare|local|readonly|typeset NAME=value ...`
// into a simple command whose argv holds the NAME=value words.
func (c *converter) convertDecl(d *syntax.DeclClause, stmt *syntax.Stmt, ctx ir.Context) *ir.Command {
	name := ir.ArgValue{Raw: d.Variant.Value, Value: d.Variant.Value, Confidence: ir.ConfStatic}
	sc := &ir.SimpleCommand{Program: name, Argv: []ir.ArgValue{name}}
	for _, as := range d.Args {
		sc.Argv = append(sc.Argv, c.assignValue(as))
	}
	return &ir.Command{
		ID:       c.nextID("simple"),
		Kind:     ir.KindSimple,
		Simple:   sc,
		Children: c.substitutions(d, ctx),
		Source:   sourceSpan(stmt, c.src),
		Context:  ctx,
	}
}

// assignValue renders one declaration argument as a word: a flag or bare
// name, or NAME=value. A value that is not static keeps the NAME= prefix
// static so the variable name can still be checked.
func (c *converter) assignValue(as *syntax.Assign) ir.ArgValue {
	raw := ""
	if start, end := int(as.Pos().Offset()), int(as.End().Offset()); start >= 0 && end <= len(c.src) && start <= end {
		raw = c.src[start:end]
	}
	if as.Naked {
		if as.Name != nil {
			return ir.ArgValue{Raw: raw, Value: as.Name.Value, Confidence: ir.ConfStatic}
		}
		return c.wordValue(as.Value)
	}
	prefix := ""
	if as.Name != nil {
		prefix = as.Name.Value
	}
	if as.Append {
		prefix += "+="
	} else {
		prefix += "="
	}
	switch {
	case as.Array != nil:
		return ir.ArgValue{Raw: raw, Value: prefix + "\x00", Confidence: ir.ConfPartiallyStatic}
	case as.Value != nil:
		v := c.wordValue(as.Value)
		if v.Confidence == ir.ConfDynamic {
			return ir.ArgValue{Raw: raw, Value: prefix + "\x00", Confidence: ir.ConfPartiallyStatic}
		}
		return ir.ArgValue{Raw: raw, Value: prefix + v.Value, Confidence: v.Confidence}
	}
	return ir.ArgValue{Raw: raw, Value: prefix, Confidence: ir.ConfStatic}
}

// substitutions converts every command and process substitution nested
// anywhere under node (arguments, assignments, ${x:-$(cmd)}, arithmetic).
func (c *converter) substitutions(node syntax.Node, ctx ir.Context) []*ir.Command {
	var out []*ir.Command
	syntax.Walk(node, func(n syntax.Node) bool {
		switch v := n.(type) {
		case *syntax.CmdSubst:
			out = append(out, c.partInnerCommands(v, ctx)...)
			return false
		case *syntax.ProcSubst:
			out = append(out, c.partInnerCommands(v, ctx)...)
			return false
		}
		return true
	})
	return out
}

func (c *converter) convertBinary(b *syntax.BinaryCmd, ctx ir.Context) *ir.Command {
	switch b.Op {
	case syntax.Pipe, syntax.PipeAll:
		// Flatten chained pipes into a single pipeline.
		pipe := &ir.Command{
			ID:      c.nextID("pipeline"),
			Kind:    ir.KindPipeline,
			Context: ctx,
		}
		pctx := ctx
		pctx.InPipeline = true
		c.flattenPipeline(b, pipe, pctx)
		return pipe

	case syntax.AndStmt:
		return &ir.Command{
			ID:   c.nextID("and"),
			Kind: ir.KindAnd,
			Children: []*ir.Command{
				c.convertStmt(b.X, ctx),
				c.convertStmt(b.Y, ctx),
			},
			Context: ctx,
		}

	case syntax.OrStmt:
		return &ir.Command{
			ID:   c.nextID("or"),
			Kind: ir.KindOr,
			Children: []*ir.Command{
				c.convertStmt(b.X, ctx),
				c.convertStmt(b.Y, ctx),
			},
			Context: ctx,
		}
	}
	// Fallback: treat as sequence.
	return &ir.Command{
		ID:   c.nextID("seq"),
		Kind: ir.KindSequence,
		Children: []*ir.Command{
			c.convertStmt(b.X, ctx),
			c.convertStmt(b.Y, ctx),
		},
		Context: ctx,
	}
}

func (c *converter) flattenPipeline(b *syntax.BinaryCmd, pipe *ir.Command, ctx ir.Context) {
	if inner, ok := b.X.Cmd.(*syntax.BinaryCmd); ok && (inner.Op == syntax.Pipe || inner.Op == syntax.PipeAll) {
		c.flattenPipeline(inner, pipe, ctx)
		// Apply redirects from b.X if any
		left := c.convertStmt(b.X, ctx)
		_ = left // already added through recursion
	} else {
		pipe.Children = append(pipe.Children, c.convertStmt(b.X, ctx))
	}
	pipe.Children = append(pipe.Children, c.convertStmt(b.Y, ctx))
}

func (c *converter) convertCall(call *syntax.CallExpr, stmt *syntax.Stmt, ctx ir.Context) *ir.Command {
	sc := &ir.SimpleCommand{}
	for _, a := range call.Assigns {
		if a.Name != nil {
			val := ir.ArgValue{Confidence: ir.ConfStatic}
			if a.Value != nil {
				val = c.wordValue(a.Value)
			}
			sc.Assignments = append(sc.Assignments, ir.Assignment{Name: a.Name.Value, Value: val})
		}
	}
	for _, w := range call.Args {
		sc.Argv = append(sc.Argv, c.wordValue(w))
	}
	if len(sc.Argv) > 0 {
		sc.Program = sc.Argv[0]
	}

	// Command / process substitutions anywhere in the arguments or the
	// leading assignments become child IR nodes so policy can audit them.
	children := c.substitutions(call, ctx)

	out := &ir.Command{
		ID:       c.nextID("simple"),
		Kind:     ir.KindSimple,
		Simple:   sc,
		Children: children,
		Source:   sourceSpan(stmt, c.src),
		Context:  ctx,
	}
	return out
}

// partInnerCommands extracts command-substitution and process-substitution
// nested commands from a WordPart. They become Children of the surrounding
// simple command so they can be audited.
func (c *converter) partInnerCommands(p syntax.WordPart, ctx ir.Context) []*ir.Command {
	var out []*ir.Command
	switch v := p.(type) {
	case *syntax.CmdSubst:
		nctx := ctx
		nctx.Depth++
		nctx.InCommandSubstitution = true
		inner := c.convertStmts(v.Stmts, nctx)
		out = append(out, &ir.Command{
			ID:       c.nextID("cmdsubst"),
			Kind:     ir.KindCommandSubstitution,
			Children: []*ir.Command{inner},
			Context:  ctx,
		})
	case *syntax.ProcSubst:
		nctx := ctx
		nctx.Depth++
		nctx.InProcessSubstitution = true
		inner := c.convertStmts(v.Stmts, nctx)
		out = append(out, &ir.Command{
			ID:       c.nextID("procsubst"),
			Kind:     ir.KindProcessSubstitution,
			Children: []*ir.Command{inner},
			Context:  ctx,
		})
	case *syntax.DblQuoted:
		for _, ip := range v.Parts {
			out = append(out, c.partInnerCommands(ip, ctx)...)
		}
	}
	return out
}

// wordValue resolves a syntax.Word to an ArgValue. It tries to produce a
// static string when the word is composed only of literals; otherwise it
// marks the value as dynamic / partially_static.
func (c *converter) wordValue(w *syntax.Word) ir.ArgValue {
	if w == nil {
		return ir.ArgValue{Confidence: ir.ConfStatic}
	}
	raw := wordRawText(w, c.src)
	val, conf := wordStaticValue(w)
	return ir.ArgValue{Raw: raw, Value: val, Confidence: conf}
}

// wordStaticValue returns the resolved static text and a confidence.
// Single-quoted strings, literals, and double-quoted strings of literals
// are static; anything containing $vars, command substitutions, etc. is
// dynamic or partially_static depending on whether any literal text was
// recovered.
func wordStaticValue(w *syntax.Word) (string, ir.Confidence) {
	var sb strings.Builder
	hasDynamic := false
	hasStatic := false
	for _, p := range w.Parts {
		switch v := p.(type) {
		case *syntax.Lit:
			sb.WriteString(unescape(v.Value, ""))
			hasStatic = true
		case *syntax.SglQuoted:
			sb.WriteString(v.Value)
			hasStatic = true
		case *syntax.DblQuoted:
			for _, ip := range v.Parts {
				switch iv := ip.(type) {
				case *syntax.Lit:
					sb.WriteString(unescape(iv.Value, "$`\"\\\n"))
					hasStatic = true
				default:
					hasDynamic = true
					sb.WriteString("\x00")
				}
			}
		default:
			hasDynamic = true
		}
	}
	val := sb.String()
	if hasDynamic && hasStatic {
		return val, ir.ConfPartiallyStatic
	}
	if hasDynamic {
		return "", ir.ConfDynamic
	}
	return val, ir.ConfStatic
}

// unescape removes shell backslash escapes from literal text: every `\x`
// when only is empty (unquoted text), or just the characters in only
// (inside double quotes). `\<newline>` is a line continuation and vanishes.
func unescape(lit, only string) string {
	if !strings.Contains(lit, "\\") {
		return lit
	}
	var sb strings.Builder
	for i := 0; i < len(lit); i++ {
		if lit[i] == '\\' && i+1 < len(lit) && (only == "" || strings.IndexByte(only, lit[i+1]) >= 0) {
			i++
			if lit[i] != '\n' {
				sb.WriteByte(lit[i])
			}
			continue
		}
		sb.WriteByte(lit[i])
	}
	return sb.String()
}

func wordRawText(w *syntax.Word, src string) string {
	if w == nil {
		return ""
	}
	start := int(w.Pos().Offset())
	end := int(w.End().Offset())
	if start >= 0 && end <= len(src) && start <= end {
		return src[start:end]
	}
	// Fall back to recomposed literal value.
	val, _ := wordStaticValue(w)
	return val
}

func (c *converter) convertRedirects(rs []*syntax.Redirect) []ir.Redirect {
	out := make([]ir.Redirect, 0, len(rs))
	for _, r := range rs {
		op := mapRedirOp(r.Op)
		fd := ""
		if r.N != nil {
			fd = r.N.Value
		}
		out = append(out, ir.Redirect{
			Op:     op,
			FD:     fd,
			Target: c.wordValue(r.Word),
		})
	}
	return out
}

func mapRedirOp(op syntax.RedirOperator) ir.RedirectOp {
	switch op {
	case syntax.RdrIn:
		return ir.RedirIn
	case syntax.RdrOut:
		return ir.RedirOut
	case syntax.AppOut:
		return ir.RedirAppend
	case syntax.Hdoc, syntax.DashHdoc:
		return ir.RedirHeredoc
	case syntax.DplOut:
		return ir.RedirDupOut
	case syntax.DplIn:
		return ir.RedirDupIn
	case syntax.RdrAll:
		return ir.RedirOut
	case syntax.AppAll:
		return ir.RedirAppend
	case syntax.ClbOut:
		return ir.RedirClobber
	case syntax.RdrInOut:
		return ir.RedirReadWrite
	}
	return ir.RedirOther
}

func sourceSpan(stmt *syntax.Stmt, src string) ir.SourceSpan {
	if stmt == nil {
		return ir.SourceSpan{}
	}
	span := ir.SourceSpan{
		StartLine: stmt.Pos().Line(),
		StartCol:  stmt.Pos().Col(),
		EndLine:   stmt.End().Line(),
		EndCol:    stmt.End().Col(),
	}
	start := int(stmt.Pos().Offset())
	end := int(stmt.End().Offset())
	if start >= 0 && end <= len(src) && start <= end {
		span.Text = src[start:end]
	}
	return span
}

// FormatPos is a small helper used by error messages.
func FormatPos(line, col uint) string {
	return strconv.FormatUint(uint64(line), 10) + ":" + strconv.FormatUint(uint64(col), 10)
}
