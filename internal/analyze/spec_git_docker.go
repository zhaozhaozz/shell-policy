package analyze

import (
	"github.com/self/shell_permission/internal/argv"
	"github.com/self/shell_permission/internal/ir"
	"github.com/self/shell_permission/internal/paths"
)

func init() {
	// gitReadSubs is the set of git subcommands that only read state.
	gitReadSubs := map[string]bool{
		"status": true, "diff": true, "log": true, "show": true,
		"rev-parse": true, "ls-files": true, "ls-tree": true, "blame": true,
		"branch": true, "tag": true, "remote": true, "config": true,
		"describe": true, "stash": true, "shortlog": true,
	}
	gitWriteSubs := map[string]bool{
		"add": true, "commit": true, "checkout": true, "restore": true,
		"reset": true, "rm": true, "mv": true, "merge": true, "rebase": true,
		"cherry-pick": true, "revert": true, "clean": true, "switch": true,
		"apply": true, "am": true, "init": true,
	}
	gitNetworkSubs := map[string]bool{
		"push": true, "pull": true, "fetch": true, "clone": true, "remote": true,
	}

	register([]string{"git"}, &commandSpec{
		Argv: argv.Spec{
			StopAtFirstPositional: true,
			Flags: map[string]argv.FlagSpec{
				"chdir":    {Names: []string{"-C"}, TakesValue: true},
				"gitDir":   {Names: []string{"--git-dir"}, TakesValue: true},
				"workTree": {Names: []string{"--work-tree"}, TakesValue: true},
				"version":  {Names: []string{"--version"}},
				"help":     {Names: []string{"-h", "--help"}},
			},
		},
		Subcommand: func(p *argv.Parsed) []string {
			out := []string{"git"}
			if len(p.Positionals) > 0 && p.Positionals[0].Confidence == ir.ConfStatic {
				out = append(out, p.Positionals[0].Value)
			}
			return out
		},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			sub := ""
			rest := p.Positionals
			if len(rest) > 0 {
				sub = rest[0].Value
				rest = rest[1:]
			}

			// Writes act on the repository: the -C directory or the cwd, so
			// rules can tell whether it lies in a writable directory.
			repo := r.ResolveString(".")
			if dir := stringFlag(p, "chdir"); dir != "" {
				repo = r.ResolveString(dir)
			}
			if _, ok := p.Flags["gitDir"]; ok || p.Flags["workTree"] != nil || p.HasDynamic && p.Flags["chdir"] != nil {
				repo = ir.NormalizedPath{Raw: "<repository>", Kind: ir.PathDynamic, Scope: ir.ScopeUnknown, Confidence: ir.ConfDynamic}
			}
			repoPaths := []ir.NormalizedPath{repo}

			ops := []ir.ResourceOp{}
			switch {
			case sub == "":
				ops = append(ops, ir.ResourceOp{
					Type:       ir.OpGitRead,
					Confidence: confOf(c.Simple),
					Context:    c.Context,
				})
			case gitNetworkSubs[sub]:
				opType := ir.OpNetworkWrite
				if sub == "fetch" || sub == "pull" || sub == "clone" {
					opType = ir.OpNetworkRead
				}
				ops = append(ops, ir.ResourceOp{
					Type:       opType,
					Subcommand: []string{"git", sub},
					Confidence: confOf(c.Simple),
					Context:    c.Context,
				})
				ops = append(ops, ir.ResourceOp{
					Type:       ir.OpGitWrite,
					Paths:      repoPaths,
					Subcommand: []string{"git", sub},
					Confidence: confOf(c.Simple),
					Context:    c.Context,
				})
			case gitWriteSubs[sub]:
				ops = append(ops, ir.ResourceOp{
					Type:       ir.OpGitWrite,
					Paths:      repoPaths,
					Subcommand: []string{"git", sub},
					Confidence: confOf(c.Simple),
					Context:    c.Context,
				})
				if sub == "clean" || sub == "rm" {
					ops = append(ops, ir.ResourceOp{
						Type:       ir.OpFileDelete,
						Paths:      repoPaths,
						Subcommand: []string{"git", sub},
						Confidence: confOf(c.Simple),
						Context:    c.Context,
					})
				}
			case gitReadSubs[sub]:
				ops = append(ops, ir.ResourceOp{
					Type:       ir.OpGitRead,
					Subcommand: []string{"git", sub},
					Confidence: confOf(c.Simple),
					Context:    c.Context,
				})
			default:
				ops = append(ops, ir.ResourceOp{
					Type:       ir.OpUnknown,
					Subcommand: []string{"git", sub},
					Confidence: confOf(c.Simple),
					Context:    c.Context,
				})
			}
			// Surface flags after the subcommand for downstream rule
			// matching (e.g. `git push --force`).
			flags := map[string]any{}
			for _, a := range rest {
				if a.Confidence == ir.ConfStatic {
					if a.Value == "--force" || a.Value == "-f" {
						flags["force"] = true
					}
					if a.Value == "--mirror" {
						flags["mirror"] = true
					}
					if a.Value == "--hard" {
						flags["hard"] = true
					}
					if a.Value == "-fdx" || a.Value == "-fd" || a.Value == "-fx" {
						flags["forceDirsX"] = true
					}
				}
			}
			if c.Simple.Flags == nil {
				c.Simple.Flags = map[string]any{}
			}
			for k, v := range flags {
				c.Simple.Flags[k] = v
			}
			return ops
		},
	})

	// docker / podman
	register([]string{"docker", "podman"}, &commandSpec{
		Argv: argv.Spec{
			StopAtFirstPositional: true,
		},
		Subcommand: func(p *argv.Parsed) []string {
			out := []string{"docker"}
			if len(p.Positionals) > 0 && p.Positionals[0].Confidence == ir.ConfStatic {
				out = append(out, p.Positionals[0].Value)
			}
			return out
		},
		Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
			sub := ""
			if len(p.Positionals) > 0 {
				sub = p.Positionals[0].Value
			}
			readSubs := map[string]bool{
				"ps": true, "images": true, "image": true, "inspect": true,
				"version": true, "info": true, "history": true, "port": true,
				"logs": true, "stats": true, "top": true, "diff": true,
			}
			writeSubs := map[string]bool{
				"rm": true, "rmi": true, "kill": true, "stop": true, "start": true,
				"restart": true, "pause": true, "unpause": true, "create": true,
				"build": true, "tag": true, "push": true, "pull": true, "cp": true,
				"commit": true,
			}
			ops := []ir.ResourceOp{}
			switch {
			case readSubs[sub]:
				ops = append(ops, ir.ResourceOp{
					Type:       ir.OpContainerRead,
					Subcommand: []string{"docker", sub},
					Confidence: confOf(c.Simple),
					Context:    c.Context,
				})
			case writeSubs[sub]:
				ops = append(ops, ir.ResourceOp{
					Type:       ir.OpContainerWrite,
					Subcommand: []string{"docker", sub},
					Confidence: confOf(c.Simple),
					Context:    c.Context,
				})
			case sub == "system":
				ops = append(ops, ir.ResourceOp{
					Type:       ir.OpContainerWrite,
					Subcommand: []string{"docker", "system"},
					Confidence: confOf(c.Simple),
					Context:    c.Context,
				})
			default:
				// `exec` and `run` are handled by the wrapper detector.
				ops = append(ops, ir.ResourceOp{
					Type:       ir.OpUnknown,
					Subcommand: []string{"docker", sub},
					Confidence: confOf(c.Simple),
					Context:    c.Context,
				})
			}
			return ops
		},
	})
}
