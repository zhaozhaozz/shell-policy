package analyze

import (
	"path/filepath"
	"strings"

	"github.com/zhaozhaozz/shell-policy/internal/ir"
	"github.com/zhaozhaozz/shell-policy/internal/paths"
)

// gitReadOnly are subcommands that only read the repository whatever their
// options (an --output option is handled separately).
var gitReadOnly = set("status", "diff", "log", "show", "rev-parse", "ls-files", "ls-tree", "blame",
	"describe", "shortlog", "cat-file", "rev-list", "show-ref", "for-each-ref", "name-rev", "merge-base",
	"count-objects", "check-ignore", "whatchanged", "show-branch", "var", "version", "help")

var gitWrite = set("add", "commit", "checkout", "restore", "reset", "rm", "mv", "merge", "rebase",
	"cherry-pick", "revert", "clean", "switch", "apply", "am", "init", "notes", "worktree", "submodule",
	"bisect", "update-ref", "symbolic-ref", "gc", "prune", "repack", "replace", "update-index", "mergetool", "format-patch")

var gitNetwork = set("push", "pull", "fetch", "clone", "ls-remote")

// gitKind classifies a subcommand with its arguments as "read", "write",
// "network", "config" (git config that writes) or "" (unknown). Read-only
// is only granted to argument combinations known not to modify anything:
// `git branch -D`, `git tag -d`, `git stash clear` or `git config --global`
// are writes even though `git branch` alone only lists.
func gitKind(sub string, rest []ir.ArgValue) string {
	args := staticArgs(rest)
	has := func(names ...string) bool {
		for _, a := range args {
			for _, n := range names {
				if a == n || strings.HasPrefix(a, n+"=") {
					return true
				}
			}
		}
		return false
	}
	positionals := 0
	for _, a := range args {
		if a == "" || !strings.HasPrefix(a, "-") {
			positionals++
		}
	}
	switch {
	case sub == "":
		return "read"
	case sub == "grep":
		if has("-O", "--open-files-in-pager") {
			return "" // runs a pager program
		}
		return "read"
	case gitReadOnly[sub]:
		return "read"
	case gitNetwork[sub]:
		return "network"
	case gitWrite[sub]:
		return "write"
	case sub == "branch":
		if has("-d", "-D", "--delete", "-m", "-M", "--move", "-c", "-C", "--copy", "-f", "--force",
			"-u", "--set-upstream-to", "--unset-upstream", "--edit-description", "-t", "--track") {
			return "write"
		}
		// A name without a listing option creates a branch.
		if positionals > 0 && !has("-l", "--list", "--contains", "--no-contains", "--merged", "--no-merged", "--points-at") {
			return "write"
		}
		return "read"
	case sub == "tag":
		if has("-d", "--delete", "-a", "--annotate", "-s", "--sign", "-u", "--local-user", "-f", "--force", "-m", "--message", "-F", "--file") {
			return "write"
		}
		if positionals > 0 && !has("-l", "--list", "-v", "--verify", "--contains", "--no-contains", "--merged", "--no-merged", "--points-at") {
			return "write"
		}
		return "read"
	case sub == "stash":
		if len(args) > 0 && (args[0] == "list" || args[0] == "show") {
			return "read"
		}
		return "write" // push (the default), pop, apply, drop, clear ...
	case sub == "reflog":
		if len(args) == 0 || args[0] == "show" || strings.HasPrefix(args[0], "-") {
			return "read"
		}
		return "write" // expire, delete
	case sub == "remote":
		if len(args) == 0 || args[0] == "-v" || args[0] == "--verbose" || args[0] == "get-url" {
			return "read"
		}
		if args[0] == "show" || args[0] == "update" || args[0] == "prune" {
			return "network"
		}
		return "write"
	case sub == "config":
		return gitConfigKind(args)
	}
	return ""
}

// gitConfigKind tells reading git config (get, list, a single name) from
// writing it.
func gitConfigKind(args []string) string {
	var names []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--get" || a == "--get-all" || a == "--get-regexp" || a == "--get-urlmatch" || a == "-l" ||
			a == "--list" || a == "--get-color" || a == "--get-colorbool":
			return "read"
		case a == "-f" || a == "--file" || a == "--blob":
			i++ // the option's value
		case strings.HasPrefix(a, "-"):
		default:
			names = append(names, a)
		}
	}
	if len(names) > 0 && (names[0] == "get" || names[0] == "list") {
		return "read"
	}
	if len(names) == 1 && names[0] != "" && names[0] != "set" && names[0] != "unset" && names[0] != "edit" {
		return "read" // git config <name>
	}
	return "config"
}

// gitConfigFile is the file a git config write touches.
func gitConfigFile(rest []ir.ArgValue, repo ir.NormalizedPath, r *paths.Resolver) ir.NormalizedPath {
	for i, a := range rest {
		switch v := a.Value; {
		case v == "--global":
			return r.ResolveString("~/.gitconfig")
		case v == "--system":
			return r.ResolveString("/etc/gitconfig")
		case (v == "-f" || v == "--file") && i+1 < len(rest):
			return r.Resolve(rest[i+1])
		case strings.HasPrefix(v, "--file="):
			return r.ResolveString(strings.TrimPrefix(v, "--file="))
		}
	}
	if repo.Absolute != "" {
		return r.ResolveString(filepath.Join(repo.Absolute, ".git", "config"))
	}
	return repo
}

// gitOutputArg finds --output=<file> / --output <file>.
func gitOutputArg(rest []ir.ArgValue) *ir.ArgValue {
	for i, a := range rest {
		if v, ok := strings.CutPrefix(a.Value, "--output="); ok && a.Confidence == ir.ConfStatic {
			return &ir.ArgValue{Raw: v, Value: v, Confidence: ir.ConfStatic}
		}
		if a.Value == "--output" && i+1 < len(rest) {
			return &rest[i+1]
		}
		if a.Confidence != ir.ConfStatic && strings.Contains(a.Raw, "--output") {
			return &ir.ArgValue{Raw: a.Raw, Confidence: ir.ConfDynamic}
		}
	}
	return nil
}
