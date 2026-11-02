package analyze

import (
	"strings"

	"github.com/self/shell_permission/internal/argv"
	"github.com/self/shell_permission/internal/ir"
	"github.com/self/shell_permission/internal/paths"
)

// packageManagers maps a package manager to its subcommands that install,
// remove or upgrade packages. Other subcommands (list, search, run, build)
// are left to the remaining rules.
var packageManagers = map[string]map[string]bool{
	"apt":      set("install", "reinstall", "remove", "purge", "upgrade", "full-upgrade", "dist-upgrade", "autoremove", "update"),
	"apt-get":  set("install", "reinstall", "remove", "purge", "upgrade", "dist-upgrade", "autoremove", "update", "build-dep"),
	"aptitude": set("install", "reinstall", "remove", "purge", "upgrade", "safe-upgrade", "full-upgrade", "update"),
	"dpkg":     set("-i", "--install", "-r", "--remove", "-P", "--purge", "--configure"),
	"yum":      set("install", "reinstall", "remove", "erase", "update", "upgrade", "downgrade", "groupinstall", "localinstall"),
	"dnf":      set("install", "reinstall", "remove", "erase", "update", "upgrade", "downgrade", "autoremove", "distro-sync"),
	"rpm":      set("-i", "--install", "-U", "--upgrade", "-e", "--erase", "-F", "--freshen"),
	"zypper":   set("install", "in", "remove", "rm", "update", "up", "dist-upgrade", "dup", "patch"),
	"pacman":   set("-S", "-Syu", "-Sy", "-Su", "-R", "-Rs", "-Rns", "-U", "--sync", "--remove", "--upgrade"),
	"apk":      set("add", "del", "upgrade", "update", "fix"),
	"brew":     set("install", "reinstall", "uninstall", "remove", "rm", "upgrade", "update", "tap", "untap", "link", "unlink"),
	"snap":     set("install", "remove", "refresh", "revert"),
	"flatpak":  set("install", "uninstall", "update"),
	"port":     set("install", "uninstall", "upgrade", "selfupdate"),
	"pip":      set("install", "uninstall", "download"),
	"pip3":     set("install", "uninstall", "download"),
	"pipx":     set("install", "uninstall", "upgrade", "reinstall", "inject", "run"),
	"uv":       set("add", "remove", "sync", "pip", "tool"),
	"conda":    set("install", "remove", "uninstall", "update", "upgrade", "create"),
	"mamba":    set("install", "remove", "uninstall", "update", "upgrade", "create"),
	"npm":      set("install", "i", "add", "ci", "uninstall", "remove", "rm", "un", "update", "up", "upgrade", "link", "ln", "publish", "unpublish", "exec", "x"),
	"pnpm":     set("install", "i", "add", "remove", "rm", "uninstall", "update", "up", "upgrade", "link", "publish", "dlx", "exec"),
	"yarn":     set("", "install", "add", "remove", "upgrade", "up", "global", "link", "publish", "dlx"),
	"bun":      set("install", "i", "add", "remove", "rm", "update", "upgrade", "link", "x"),
	"npx":      set("*"),
	"bunx":     set("*"),
	"gem":      set("install", "uninstall", "update"),
	"bundle":   set("", "install", "update", "add", "remove"),
	"cargo":    set("install", "uninstall", "add", "remove", "update"),
	"go":       set("install", "get"),
	"composer": set("install", "require", "remove", "update", "upgrade", "global"),
}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

func init() {
	for name, subs := range packageManagers {
		subs := subs
		register([]string{name}, &commandSpec{
			Argv: argv.Spec{},
			Operations: func(c *ir.Command, p *argv.Parsed, r *paths.Resolver) []ir.ResourceOp {
				sub, dynamic := packageSubcommand(c.Simple.Argv[1:], subs)
				if !dynamic && !subs["*"] && !subs[sub] && !(len(sub) > 2 && sub[0] == '-' && subs[sub[:2]]) {
					return []ir.ResourceOp{{Type: ir.OpUnknown, Subcommand: []string{name, sub}, Confidence: confOf(c.Simple), Context: c.Context}}
				}
				return []ir.ResourceOp{{
					Type:       ir.OpPackageInstall,
					Target:     name,
					Subcommand: []string{name, sub},
					Confidence: confOf(c.Simple),
					Dynamic:    dynamic,
					Context:    c.Context,
				}}
			},
		})
	}
}

// packageSubcommand returns the word that selects the action: the first
// non-option word, or an action option for option-driven managers (pacman
// -Syu, dpkg -i, rpm -ivh). dynamic is true when that word is not static.
func packageSubcommand(args []ir.ArgValue, subs map[string]bool) (string, bool) {
	for _, a := range args {
		if a.Confidence != ir.ConfStatic {
			return "", true
		}
		v := a.Value
		if !strings.HasPrefix(v, "-") {
			return v, false
		}
		if subs[v] || len(v) > 2 && v[1] != '-' && subs[v[:2]] {
			return v, false
		}
	}
	return "", false
}
