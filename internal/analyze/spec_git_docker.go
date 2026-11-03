package analyze

import (
	"strings"

	"github.com/zhaozhaozz/shell-policy/internal/argv"
	"github.com/zhaozhaozz/shell-policy/internal/ir"
	"github.com/zhaozhaozz/shell-policy/internal/paths"
)

func init() {
	register([]string{"git"}, &commandSpec{
		Argv: argv.Spec{
			StopAtFirstPositional: true,
			Flags: map[string]argv.FlagSpec{
				"chdir":    {Names: []string{"-C"}, TakesValue: true},
				"gitDir":   {Names: []string{"--git-dir"}, TakesValue: true},
				"workTree": {Names: []string{"--work-tree"}, TakesValue: true},
				"version":  {Names: []string{"--version"}},
				"help":     {Names: []string{"-h", "--help"}},
				"noPager":  {Names: []string{"--no-pager", "-P"}},
				// -c / --config-env can set core.pager, hooks and other
				// commands git runs: the command is no longer read-only.
				"config": {Names: []string{"-c", "--config-env"}, TakesValue: true, Repeatable: true},
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

			op := func(t ir.OpType, paths []ir.NormalizedPath) ir.ResourceOp {
				return ir.ResourceOp{Type: t, Paths: paths, Subcommand: []string{"git", sub}, Confidence: confOf(c.Simple), Context: c.Context}
			}
			// Options before the subcommand other than the known safe ones
			// (for example -c, --exec-path) can make git run other programs.
			if p.Flags["config"] != nil || len(p.RawFlags) > 0 {
				return []ir.ResourceOp{op(ir.OpUnknown, nil)}
			}

			ops := []ir.ResourceOp{}
			switch kind := gitKind(sub, rest); kind {
			case "read":
				ops = append(ops, op(ir.OpGitRead, nil))
			case "network":
				opType := ir.OpNetworkWrite
				if sub == "fetch" || sub == "pull" || sub == "clone" || sub == "remote" {
					opType = ir.OpNetworkRead
				}
				ops = append(ops, op(opType, nil), op(ir.OpGitWrite, repoPaths))
			case "write":
				ops = append(ops, op(ir.OpGitWrite, repoPaths))
				if sub == "clean" || sub == "rm" {
					ops = append(ops, op(ir.OpFileDelete, repoPaths))
				}
			case "config":
				// git config writes the file of its scope.
				ops = append(ops, op(ir.OpFileWrite, []ir.NormalizedPath{gitConfigFile(rest, repo, r)}))
			default:
				ops = append(ops, op(ir.OpUnknown, nil))
			}
			// --output writes a file wherever it points (log, diff, show ...).
			if out := gitOutputArg(rest); out != nil {
				ops = append(ops, op(ir.OpFileWrite, pathsFromArgs([]ir.ArgValue{*out}, r)))
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
			op := func(t ir.OpType) ir.ResourceOp {
				return ir.ResourceOp{Type: t, Subcommand: []string{"docker", sub}, Confidence: confOf(c.Simple), Context: c.Context}
			}
			ops := []ir.ResourceOp{}
			switch dockerKind(staticArgs(p.Positionals)) {
			case "read":
				ops = append(ops, op(ir.OpContainerRead))
			case "write":
				ops = append(ops, op(ir.OpContainerWrite))
			default:
				// `exec` and `run` are handled by the wrapper detector.
				ops = append(ops, op(ir.OpUnknown))
			}
			return ops
		},
	})
}

// dockerReadTop are top-level docker commands that only read.
var dockerReadTop = set("ps", "images", "inspect", "version", "info", "history", "port", "logs", "stats", "top", "diff", "events")

var dockerWriteTop = set("rm", "rmi", "kill", "stop", "start", "restart", "pause", "unpause", "create", "build",
	"tag", "push", "pull", "cp", "commit", "rename", "update", "load", "import", "save", "export", "login", "logout", "attach", "wait")

// dockerReadVerbs are the read-only verbs of management commands
// (docker image ls, docker container inspect, docker system df ...).
var dockerReadVerbs = set("ls", "list", "inspect", "history", "logs", "top", "port", "diff", "stats", "df", "info", "events", "ps", "config", "images", "version")

var dockerManagement = set("image", "container", "network", "volume", "system", "builder", "buildx", "compose",
	"context", "plugin", "secret", "config", "node", "service", "stack", "trust", "manifest")

// dockerKind classifies a docker / podman command line as "read",
// "write" or "" (unknown). Management commands are judged by their verb:
// `docker image ls` reads, `docker image prune` writes.
func dockerKind(args []string) string {
	if len(args) == 0 {
		return ""
	}
	sub := args[0]
	switch {
	case dockerReadTop[sub]:
		return "read"
	case dockerWriteTop[sub]:
		return "write"
	case dockerManagement[sub]:
		verb := ""
		for _, a := range args[1:] {
			if a != "" && !strings.HasPrefix(a, "-") {
				verb = a
				break
			}
		}
		if dockerReadVerbs[verb] {
			return "read"
		}
		return "write"
	}
	return ""
}
