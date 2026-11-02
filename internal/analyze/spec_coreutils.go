package analyze

import (
	"strings"

	"github.com/self/shell_permission/internal/argv"
	"github.com/self/shell_permission/internal/ir"
	"github.com/self/shell_permission/internal/paths"
)

func init() {
	register([]string{"ls", "dir"}, &commandSpec{
		Argv: argv.Spec{
			Flags: map[string]argv.FlagSpec{
				"all":       {Names: []string{"-a", "--all"}},
				"long":      {Names: []string{"-l"}},
				"recursive": {Names: []string{"-R", "--recursive"}},
				"human":     {Names: []string{"-h", "--human-readable"}},
			},
		},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			args := p.Positionals
			if len(args) == 0 {
				args = []ir.ArgValue{{Raw: ".", Value: ".", Confidence: ir.ConfStatic}}
			}
			return []ir.ResourceOp{{
				Type:       ir.OpFileList,
				Paths:      pathsFromArgs(args, r),
				Flags:      p.Flags,
				Confidence: confOf(c.Simple),
				Dynamic:    p.HasDynamic,
				Context:    c.Context,
			}}
		},
	})

	register([]string{"cat", "head", "tail", "less", "more", "bat"}, &commandSpec{
		Argv: argv.Spec{
			Flags: map[string]argv.FlagSpec{
				"follow": {Names: []string{"-f", "--follow"}},
				"lines":  {Names: []string{"-n", "--lines"}, TakesValue: true},
				"bytes":  {Names: []string{"-c", "--bytes"}, TakesValue: true},
			},
		},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			if len(p.Positionals) == 0 {
				return nil
			}
			return []ir.ResourceOp{{
				Type:       ir.OpFileRead,
				Paths:      pathsFromArgs(p.Positionals, r),
				Flags:      p.Flags,
				Confidence: confOf(c.Simple),
				Dynamic:    p.HasDynamic,
				Context:    c.Context,
			}}
		},
	})

	register([]string{"stat", "file"}, &commandSpec{
		Argv: argv.Spec{},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			return []ir.ResourceOp{{
				Type:       ir.OpFileReadMetadata,
				Paths:      pathsFromArgs(p.Positionals, r),
				Confidence: confOf(c.Simple),
				Dynamic:    p.HasDynamic,
				Context:    c.Context,
			}}
		},
	})

	register([]string{"echo", "printf"}, &commandSpec{
		Argv: argv.Spec{},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			// echo writes to stdout. Real file write only happens via
			// redirection, which the analyzer handles separately.
			return nil
		},
	})

	register([]string{"grep", "egrep", "fgrep", "rg"}, &commandSpec{
		Argv: argv.Spec{
			Flags: map[string]argv.FlagSpec{
				"recursive":  {Names: []string{"-r", "-R", "--recursive"}},
				"ignoreCase": {Names: []string{"-i", "--ignore-case"}},
				"pattern":    {Names: []string{"-e", "--regexp"}, TakesValue: true, Repeatable: true},
				"file":       {Names: []string{"-f", "--file"}, TakesValue: true},
				// rg --pre runs a program on every file it searches.
				"pre":     {Names: []string{"--pre"}, TakesValue: true},
				"preGlob": {Names: []string{"--pre-glob"}, TakesValue: true},
			},
		},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			// First positional is pattern unless -e provided; remaining are files.
			args := p.Positionals
			if _, ok := p.Flags["pattern"]; !ok && len(args) > 0 {
				args = args[1:]
			}
			var ops []ir.ResourceOp
			if pre := stringFlag(p, "pre"); pre != "" || p.Flags["pre"] != nil {
				ops = append(ops, ir.ResourceOp{Type: ir.OpProcessExec, Target: pre, Confidence: confOf(c.Simple), Context: c.Context})
			}
			if len(args) == 0 {
				return ops
			}
			return append(ops, ir.ResourceOp{
				Type:       ir.OpFileRead,
				Paths:      pathsFromArgs(args, r),
				Flags:      p.Flags,
				Confidence: confOf(c.Simple),
				Dynamic:    p.HasDynamic,
				Context:    c.Context,
			})
		},
	})

	register([]string{"rm"}, &commandSpec{
		Argv: argv.Spec{
			Flags: map[string]argv.FlagSpec{
				"recursive":   {Names: []string{"-r", "-R", "--recursive"}},
				"force":       {Names: []string{"-f", "--force"}},
				"interactive": {Names: []string{"-i", "-I", "--interactive"}},
			},
		},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			return []ir.ResourceOp{{
				Type:       ir.OpFileDelete,
				Paths:      pathsFromArgs(p.Positionals, r),
				Flags:      p.Flags,
				Confidence: confOf(c.Simple),
				Dynamic:    p.HasDynamic,
				Context:    c.Context,
			}}
		},
	})

	register([]string{"mkdir"}, &commandSpec{
		Argv: argv.Spec{
			Flags: map[string]argv.FlagSpec{
				"parents": {Names: []string{"-p", "--parents"}},
			},
		},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			return []ir.ResourceOp{{
				Type:       ir.OpFileWrite,
				Paths:      pathsFromArgs(p.Positionals, r),
				Flags:      p.Flags,
				Confidence: confOf(c.Simple),
				Dynamic:    p.HasDynamic,
				Context:    c.Context,
			}}
		},
	})

	register([]string{"touch"}, &commandSpec{
		Argv: argv.Spec{},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			return []ir.ResourceOp{{
				Type:       ir.OpFileWrite,
				Paths:      pathsFromArgs(p.Positionals, r),
				Confidence: confOf(c.Simple),
				Dynamic:    p.HasDynamic,
				Context:    c.Context,
			}}
		},
	})

	register([]string{"cp"}, &commandSpec{
		Argv: argv.Spec{
			Flags: map[string]argv.FlagSpec{
				"recursive": {Names: []string{"-r", "-R", "--recursive"}},
				"force":     {Names: []string{"-f", "--force"}},
				"preserve":  {Names: []string{"-p", "--preserve"}},
			},
		},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			args := p.Positionals
			if len(args) < 2 {
				return nil
			}
			srcs := args[:len(args)-1]
			dst := args[len(args)-1]
			return []ir.ResourceOp{
				{
					Type:       ir.OpFileRead,
					Paths:      pathsFromArgs(srcs, r),
					Confidence: confOf(c.Simple),
					Dynamic:    p.HasDynamic,
					Context:    c.Context,
				},
				{
					Type:       ir.OpFileWrite,
					Paths:      pathsFromArgs([]ir.ArgValue{dst}, r),
					Confidence: confOf(c.Simple),
					Dynamic:    p.HasDynamic,
					Context:    c.Context,
				},
			}
		},
	})

	register([]string{"mv"}, &commandSpec{
		Argv: argv.Spec{
			Flags: map[string]argv.FlagSpec{
				"force": {Names: []string{"-f", "--force"}},
			},
		},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			args := p.Positionals
			if len(args) < 2 {
				return nil
			}
			return []ir.ResourceOp{{
				Type:       ir.OpFileMove,
				Paths:      pathsFromArgs(args, r),
				Confidence: confOf(c.Simple),
				Dynamic:    p.HasDynamic,
				Context:    c.Context,
			}}
		},
	})

	register([]string{"chmod"}, &commandSpec{
		Argv: argv.Spec{
			Flags: map[string]argv.FlagSpec{
				"recursive": {Names: []string{"-R", "--recursive"}},
			},
		},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			if len(p.Positionals) < 2 {
				return nil
			}
			// First positional is mode; rest are paths.
			return []ir.ResourceOp{{
				Type:       ir.OpFileChmod,
				Paths:      pathsFromArgs(p.Positionals[1:], r),
				Flags:      p.Flags,
				Confidence: confOf(c.Simple),
				Dynamic:    p.HasDynamic,
				Context:    c.Context,
			}}
		},
	})

	register([]string{"chown"}, &commandSpec{
		Argv: argv.Spec{
			Flags: map[string]argv.FlagSpec{
				"recursive": {Names: []string{"-R", "--recursive"}},
			},
		},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			if len(p.Positionals) < 2 {
				return nil
			}
			return []ir.ResourceOp{{
				Type:       ir.OpFileChown,
				Paths:      pathsFromArgs(p.Positionals[1:], r),
				Flags:      p.Flags,
				Confidence: confOf(c.Simple),
				Dynamic:    p.HasDynamic,
				Context:    c.Context,
			}}
		},
	})

	register([]string{"ln"}, &commandSpec{
		Argv: argv.Spec{
			Flags: map[string]argv.FlagSpec{
				"symbolic": {Names: []string{"-s", "--symbolic"}},
				"force":    {Names: []string{"-f", "--force"}},
			},
		},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			return []ir.ResourceOp{{
				Type:       ir.OpFileWrite,
				Paths:      pathsFromArgs(p.Positionals, r),
				Flags:      p.Flags,
				Confidence: confOf(c.Simple),
				Dynamic:    p.HasDynamic,
				Context:    c.Context,
			}}
		},
	})

	register([]string{"sed"}, &commandSpec{
		Argv: argv.Spec{
			Flags: map[string]argv.FlagSpec{
				"inPlace": {Names: []string{"-i", "--in-place"}},
				"expr":    {Names: []string{"-e", "--expression"}, TakesValue: true, Repeatable: true},
				"file":    {Names: []string{"-f", "--file"}, TakesValue: true},
			},
		},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			args := p.Positionals
			if _, hasExpr := p.Flags["expr"]; !hasExpr && len(args) > 0 {
				args = args[1:]
			}
			ops := []ir.ResourceOp{{
				Type:       ir.OpFileRead,
				Paths:      pathsFromArgs(args, r),
				Confidence: confOf(c.Simple),
				Dynamic:    p.HasDynamic,
				Context:    c.Context,
			}}
			if boolFlag(p, "inPlace") {
				ops = append(ops, ir.ResourceOp{
					Type:       ir.OpFileWrite,
					Paths:      pathsFromArgs(args, r),
					Confidence: confOf(c.Simple),
					Dynamic:    p.HasDynamic,
					Context:    c.Context,
				})
			}
			return ops
		},
	})

	register([]string{"awk"}, &commandSpec{
		Argv: argv.Spec{
			Flags: map[string]argv.FlagSpec{
				"file": {Names: []string{"-f"}, TakesValue: true},
			},
		},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			args := p.Positionals
			if _, hasF := p.Flags["file"]; !hasF && len(args) > 0 {
				args = args[1:]
			}
			if len(args) == 0 {
				return nil
			}
			return []ir.ResourceOp{{
				Type:       ir.OpFileRead,
				Paths:      pathsFromArgs(args, r),
				Confidence: confOf(c.Simple),
				Dynamic:    p.HasDynamic,
				Context:    c.Context,
			}}
		},
	})

	register([]string{"tar"}, &commandSpec{
		Argv: argv.Spec{
			Flags: map[string]argv.FlagSpec{
				"create":  {Names: []string{"-c", "--create"}},
				"extract": {Names: []string{"-x", "--extract"}},
				"list":    {Names: []string{"-t", "--list"}},
				"file":    {Names: []string{"-f", "--file"}, TakesValue: true},
			},
		},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			ops := []ir.ResourceOp{}
			if boolFlag(p, "extract") || boolFlag(p, "create") {
				ops = append(ops, ir.ResourceOp{
					Type:       ir.OpFileWrite,
					Paths:      pathsFromArgs(p.Positionals, r),
					Confidence: confOf(c.Simple),
					Dynamic:    p.HasDynamic,
					Context:    c.Context,
				})
			} else {
				ops = append(ops, ir.ResourceOp{
					Type:       ir.OpFileRead,
					Paths:      pathsFromArgs(p.Positionals, r),
					Confidence: confOf(c.Simple),
					Dynamic:    p.HasDynamic,
					Context:    c.Context,
				})
			}
			return ops
		},
	})

	// dd uses operand=value words: if= is read, of= is written.
	register([]string{"dd"}, &commandSpec{
		Argv: argv.Spec{},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			var ops []ir.ResourceOp
			for _, a := range p.Positionals {
				key, val, ok := strings.Cut(a.Value, "=")
				if a.Confidence == ir.ConfDynamic || !ok && a.Confidence != ir.ConfStatic {
					// Unknown operand: may be of= anything.
					ops = append(ops, ir.ResourceOp{Type: ir.OpFileWrite, Paths: pathsFromArgs([]ir.ArgValue{a}, r), Confidence: ir.ConfDynamic, Dynamic: true, Context: c.Context})
					continue
				}
				opType := ir.OpType("")
				switch key {
				case "if":
					opType = ir.OpFileRead
				case "of":
					opType = ir.OpFileWrite
				}
				if opType == "" {
					continue
				}
				target := ir.ArgValue{Raw: val, Value: val, Confidence: a.Confidence}
				ops = append(ops, ir.ResourceOp{Type: opType, Paths: pathsFromArgs([]ir.ArgValue{target}, r), Confidence: a.Confidence, Dynamic: a.Confidence != ir.ConfStatic, Context: c.Context})
			}
			return ops
		},
	})

	// Network tools: curl, wget. Method flags decide read vs write.
	register([]string{"curl"}, &commandSpec{
		Argv: argv.Spec{
			Flags: map[string]argv.FlagSpec{
				"data":     {Names: []string{"-d", "--data", "--data-binary", "--data-raw", "--data-urlencode"}, TakesValue: true, Repeatable: true},
				"form":     {Names: []string{"-F", "--form"}, TakesValue: true, Repeatable: true},
				"upload":   {Names: []string{"-T", "--upload-file"}, TakesValue: true},
				"output":   {Names: []string{"-o", "--output"}, TakesValue: true},
				"request":  {Names: []string{"-X", "--request"}, TakesValue: true},
				"header":   {Names: []string{"-H", "--header"}, TakesValue: true, Repeatable: true},
				"silent":   {Names: []string{"-s", "--silent"}},
				"insecure": {Names: []string{"-k", "--insecure"}},
			},
		},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			method := stringFlag(p, "request")
			isWrite := boolFlag(p, "data") || boolFlag(p, "form") || boolFlag(p, "upload") ||
				method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE"
			target := ""
			for _, pos := range p.Positionals {
				if pos.Confidence == ir.ConfStatic {
					target = pos.Value
					break
				}
			}
			opType := ir.OpNetworkRead
			if isWrite {
				opType = ir.OpNetworkWrite
			}
			ops := []ir.ResourceOp{{
				Type:       opType,
				Target:     target,
				Confidence: confOf(c.Simple),
				Dynamic:    p.HasDynamic,
				Context:    c.Context,
			}}
			ops = append(ops, curlFileReadOps(c, p, r)...)
			if out := stringFlag(p, "output"); out != "" {
				ops = append(ops, ir.ResourceOp{
					Type:       ir.OpFileWrite,
					Paths:      []ir.NormalizedPath{r.ResolveString(out)},
					Confidence: confOf(c.Simple),
					Context:    c.Context,
				})
			}
			return ops
		},
	})

	register([]string{"wget"}, &commandSpec{
		Argv: argv.Spec{
			Flags: map[string]argv.FlagSpec{
				"output":  {Names: []string{"-O", "--output-document"}, TakesValue: true},
				"recurse": {Names: []string{"-r", "--recursive"}},
				"post":    {Names: []string{"--post-data", "--post-file"}, TakesValue: true},
			},
		},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			isWrite := boolFlag(p, "post")
			opType := ir.OpNetworkRead
			if isWrite {
				opType = ir.OpNetworkWrite
			}
			target := ""
			for _, pos := range p.Positionals {
				if pos.Confidence == ir.ConfStatic {
					target = pos.Value
					break
				}
			}
			ops := []ir.ResourceOp{{
				Type:       opType,
				Target:     target,
				Confidence: confOf(c.Simple),
				Dynamic:    p.HasDynamic,
				Context:    c.Context,
			}}
			if post := stringFlag(p, "post"); post != "" {
				ops = append(ops, ir.ResourceOp{
					Type:       ir.OpFileRead,
					Paths:      []ir.NormalizedPath{r.ResolveString(post)},
					Confidence: confOf(c.Simple),
					Dynamic:    p.HasDynamic,
					Context:    c.Context,
				})
			}
			if out := stringFlag(p, "output"); out != "" {
				ops = append(ops, ir.ResourceOp{
					Type:       ir.OpFileWrite,
					Paths:      []ir.NormalizedPath{r.ResolveString(out)},
					Confidence: confOf(c.Simple),
					Context:    c.Context,
				})
			}
			return ops
		},
	})
}

func curlFileReadOps(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
	pathsToRead := []string{}
	for _, value := range stringListFlag(p, "data") {
		if path, ok := curlAtFilePath(value); ok {
			pathsToRead = append(pathsToRead, path)
		}
	}
	for _, value := range stringListFlag(p, "form") {
		if path, ok := curlAtFilePath(value); ok {
			pathsToRead = append(pathsToRead, path)
		}
	}
	if upload := stringFlag(p, "upload"); upload != "" {
		pathsToRead = append(pathsToRead, upload)
	}

	ops := make([]ir.ResourceOp, 0, len(pathsToRead))
	for _, path := range pathsToRead {
		if path == "" {
			continue
		}
		ops = append(ops, ir.ResourceOp{
			Type:       ir.OpFileRead,
			Paths:      []ir.NormalizedPath{r.ResolveString(path)},
			Confidence: confOf(c.Simple),
			Dynamic:    p.HasDynamic,
			Context:    c.Context,
		})
	}
	return ops
}

func curlAtFilePath(value string) (string, bool) {
	if strings.HasPrefix(value, "@") {
		return strings.TrimPrefix(value, "@"), true
	}
	if idx := strings.Index(value, "=@"); idx >= 0 {
		return value[idx+2:], true
	}
	if idx := strings.Index(value, "<"); idx >= 0 && idx+1 < len(value) {
		return value[idx+1:], true
	}
	return "", false
}
