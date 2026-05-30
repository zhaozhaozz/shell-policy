// Package paths provides path normalization and classification.
//
// Normalization is *static*: there is no filesystem access and no
// environment variable expansion. Dynamic tokens (those that contain
// $vars or unresolved parts) are flagged accordingly so policy can
// refuse to silently allow them.
package paths

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/self/shell_permission/internal/ir"
)

// Resolver normalizes raw path tokens against a workspace root.
type Resolver struct {
	Cwd            string
	WorkspaceRoots []string
	Home           string
	// WritableRoots is an explicit allowlist of directories the operator
	// considers safe to modify. Paths that fall inside one of these roots
	// get NormalizedPath.Writable = true so policy rules can auto-allow
	// ordinary mutations there.
	WritableRoots []string
}

// secretPatterns is the built-in list of paths considered secret-like.
// Patterns are anchored against the path basename or full path tail.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(^|/)\.env(\..+)?$`),
	regexp.MustCompile(`(^|/)\.ssh/`),
	regexp.MustCompile(`(^|/)id_rsa(\.pub)?$`),
	regexp.MustCompile(`(^|/)id_ed25519(\.pub)?$`),
	regexp.MustCompile(`\.pem$`),
	regexp.MustCompile(`\.key$`),
	regexp.MustCompile(`\.p12$`),
	regexp.MustCompile(`(^|/)\.kube/config$`),
	regexp.MustCompile(`(^|/)\.aws/credentials$`),
	regexp.MustCompile(`(^|/)\.gcp/`),
	regexp.MustCompile(`(^|/)\.azure/`),
	regexp.MustCompile(`(^|/)\.npmrc$`),
	regexp.MustCompile(`(^|/)\.pypirc$`),
	regexp.MustCompile(`(^|/)\.netrc$`),
	regexp.MustCompile(`(^|/)credentials(\.json)?$`),
	regexp.MustCompile(`(^|/)secret`),
}

// Resolve converts an ArgValue believed to be a path into a NormalizedPath.
func (r *Resolver) Resolve(v ir.ArgValue) ir.NormalizedPath {
	raw := v.Raw
	if raw == "" {
		raw = v.Value
	}
	np := ir.NormalizedPath{Raw: raw, Confidence: v.Confidence}

	// Stdin / stdout dash.
	if raw == "-" {
		np.Kind = ir.PathStdinDash
		np.Scope = ir.ScopeStdin
		return np
	}

	// Dynamic / partially_static values: still try to classify what we can.
	if v.Confidence == ir.ConfDynamic {
		np.Kind = ir.PathDynamic
		np.Scope = ir.ScopeUnknown
		return np
	}

	// Glob detection.
	if containsGlob(raw) {
		np.Kind = ir.PathGlob
		np.Scope = ir.ScopeUnknown
		// A glob still has a (usually) static directory prefix, e.g.
		// "/var/log/*" or "build/**". Classify the scope from that prefix
		// so that dangerous globs over system paths are not silently
		// downgraded to "unknown". The expanded set is unknown, but the
		// directory being operated on is known.
		if prefix := globStaticPrefix(raw, r); prefix != "" {
			np.Scope = r.classifyScope(prefix)
			np.Writable = r.isWritable(prefix)
		}
		np.SecretCandidate = isSecretPath(raw)
		if np.SecretCandidate {
			np.Scope = ir.ScopeSecretCandidate
		}
		return np
	}

	val := v.Value
	if val == "" {
		val = raw
	}

	switch {
	case strings.HasPrefix(val, "~/") || val == "~":
		np.Kind = ir.PathHomeRelative
		if r.Home != "" {
			val = filepath.Join(r.Home, strings.TrimPrefix(val, "~"))
			np.Normalized = filepath.Clean(val)
			np.Absolute = np.Normalized
		}
	case filepath.IsAbs(val):
		np.Kind = ir.PathAbsolute
		np.Normalized = filepath.Clean(val)
		np.Absolute = np.Normalized
	default:
		np.Kind = ir.PathWorkspaceRelative
		base := r.Cwd
		if base == "" {
			base = "."
		}
		joined := filepath.Join(base, val)
		np.Normalized = filepath.Clean(joined)
		np.Absolute = np.Normalized
	}

	np.Scope = r.classifyScope(np.Absolute)
	np.Writable = r.isWritable(np.Absolute)
	np.SecretCandidate = isSecretPath(np.Absolute) || isSecretPath(raw)
	if np.SecretCandidate {
		// Secret scope wins over generic scopes for downstream rules.
		np.Scope = ir.ScopeSecretCandidate
	}
	return np
}

// isWritable reports whether abs lies within one of the configured
// writable roots. An empty allowlist means nothing is auto-writable.
func (r *Resolver) isWritable(abs string) bool {
	if abs == "" {
		return false
	}
	for _, root := range r.WritableRoots {
		if root == "" {
			continue
		}
		root = filepath.Clean(root)
		if abs == root || strings.HasPrefix(abs, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// ResolveString is a convenience wrapper for callers that have only a
// raw string. The result is treated as fully static.
func (r *Resolver) ResolveString(s string) ir.NormalizedPath {
	return r.Resolve(ir.ArgValue{Raw: s, Value: s, Confidence: ir.ConfStatic})
}

func (r *Resolver) classifyScope(abs string) ir.PathScope {
	if abs == "" {
		return ir.ScopeUnknown
	}
	switch {
	case strings.HasPrefix(abs, "/tmp"), strings.HasPrefix(abs, "/var/tmp"):
		return ir.ScopeTmp
	case isSystemPath(abs):
		return ir.ScopeSystem
	}
	for _, root := range r.WorkspaceRoots {
		if root == "" {
			continue
		}
		root = filepath.Clean(root)
		if abs == root || strings.HasPrefix(abs, root+string(filepath.Separator)) {
			return ir.ScopeInsideWorkspace
		}
	}
	if r.Home != "" {
		home := filepath.Clean(r.Home)
		if abs == home || strings.HasPrefix(abs, home+string(filepath.Separator)) {
			return ir.ScopeHome
		}
	}
	return ir.ScopeOutsideWorkspace
}

func isSystemPath(p string) bool {
	for _, prefix := range []string{
		"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64",
		"/boot", "/sys", "/proc", "/dev", "/var",
	} {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	if p == "/" {
		return true
	}
	return false
}

func containsGlob(s string) bool {
	for _, c := range s {
		if c == '*' || c == '?' {
			return true
		}
	}
	if strings.Contains(s, "[") && strings.Contains(s, "]") {
		return true
	}
	return false
}

// globStaticPrefix returns the absolute directory prefix of a glob path,
// i.e. the longest leading run of path segments that contain no glob
// metacharacters. For "/var/log/*.log" it returns "/var/log"; for
// "build/**" with cwd "/repo" it returns "/repo/build". Returns "" when
// no static prefix can be determined.
func globStaticPrefix(raw string, r *Resolver) string {
	// Strip a leading ~/ so the prefix can still be anchored to HOME.
	homePrefixed := strings.HasPrefix(raw, "~/") || raw == "~"
	cleaned := raw
	if homePrefixed && r.Home != "" {
		cleaned = filepath.Join(r.Home, strings.TrimPrefix(raw, "~"))
	}
	segs := strings.Split(cleaned, "/")
	var static []string
	for _, seg := range segs {
		if containsGlob(seg) {
			break
		}
		static = append(static, seg)
	}
	prefix := strings.Join(static, "/")
	if prefix == "" {
		// Leading segment was itself a glob (e.g. "*.log"); anchor to cwd.
		if filepath.IsAbs(cleaned) {
			return ""
		}
		if r.Cwd != "" {
			return filepath.Clean(r.Cwd)
		}
		return ""
	}
	if filepath.IsAbs(cleaned) {
		return filepath.Clean(prefix)
	}
	base := r.Cwd
	if base == "" {
		base = "."
	}
	return filepath.Clean(filepath.Join(base, prefix))
}

func isSecretPath(p string) bool {
	for _, re := range secretPatterns {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}
