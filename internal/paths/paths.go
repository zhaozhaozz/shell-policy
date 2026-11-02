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
	// Cwd is the directory relative paths are resolved against. Empty means
	// the working directory is unknown (for example after `cd "$X"`):
	// relative paths then get scope "unknown" and are never writable.
	Cwd            string
	WorkspaceRoots []string
	Home           string
	// WritableRoots is an explicit allowlist of directories the operator
	// considers safe to modify. Paths that fall inside one of these roots
	// get NormalizedPath.Writable = true so policy rules can auto-allow
	// ordinary mutations there.
	WritableRoots []string
	// SensitivePaths adds secret-like path patterns on top of the built-in
	// list (see MatchSensitive for the syntax).
	SensitivePaths []string
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
		np.SecretCandidate = r.isSecret(raw)
		if prefix := globStaticPrefix(raw, r); prefix != "" && r.isSecret(prefix) {
			np.SecretCandidate = true
		}
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
		if r.Cwd == "" {
			// Unknown working directory: the target cannot be located.
			np.Normalized = filepath.Clean(val)
			np.Scope = ir.ScopeUnknown
			np.SecretCandidate = r.isSecret(np.Normalized) || r.isSecret(raw)
			if np.SecretCandidate {
				np.Scope = ir.ScopeSecretCandidate
			}
			return np
		}
		np.Normalized = filepath.Clean(filepath.Join(r.Cwd, val))
		np.Absolute = np.Normalized
	}

	np.Scope = r.classifyScope(np.Absolute)
	np.Writable = r.isWritable(np.Absolute)
	np.SecretCandidate = r.isSecret(np.Absolute) || r.isSecret(raw)
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
	case underDir(abs, "/tmp"), underDir(abs, "/var/tmp"):
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

// underDir reports whether p is dir itself or lies below it.
func underDir(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+"/")
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
	if homePrefixed {
		if r.Home == "" {
			return ""
		}
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
		if filepath.IsAbs(cleaned) || r.Cwd == "" {
			return ""
		}
		return filepath.Clean(r.Cwd)
	}
	if filepath.IsAbs(cleaned) {
		return filepath.Clean(prefix)
	}
	if r.Cwd == "" {
		return ""
	}
	return filepath.Clean(filepath.Join(r.Cwd, prefix))
}

// isSecret applies the built-in patterns and the resolver's SensitivePaths.
func (r *Resolver) isSecret(p string) bool {
	if p == "" {
		return false
	}
	if isSecretPath(p) {
		return true
	}
	for _, pat := range r.SensitivePaths {
		if MatchSensitive(pat, p, r.Home) {
			return true
		}
	}
	return false
}

// MatchSensitive reports whether path p is covered by a sensitive-path
// pattern. Patterns are matched component by component, each component may
// be a glob (*, ?, [...]), and a match also covers everything below it:
//
//   - "/etc/app/secrets/" or "/etc/app/token" is anchored at the root;
//   - "~/.aws/" is anchored at home (raw "~/..." paths match too when the
//     home directory is unknown);
//   - a pattern without a leading / or ~ matches at any depth: ".env",
//     "*.pem", ".env.*", "config/secrets.yml".
func MatchSensitive(pattern, p, home string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || p == "" {
		return false
	}
	anchored := false
	switch {
	case pattern == "~" || strings.HasPrefix(pattern, "~/"):
		anchored = true
		if home != "" {
			pattern = filepath.Join(home, strings.TrimPrefix(pattern, "~"))
		}
	case strings.HasPrefix(pattern, "/"):
		anchored = true
	}
	pc := splitComponents(pattern)
	xc := splitComponents(p)
	if len(pc) == 0 {
		return false
	}
	last := len(xc) - len(pc)
	if anchored && last > 0 {
		last = 0
	}
	for start := 0; start <= last; start++ {
		if matchComponents(pc, xc[start:start+len(pc)]) {
			return true
		}
	}
	return false
}

// splitComponents splits a path into its non-empty components; a leading
// "/" becomes a "/" component so anchored patterns only match from the root.
func splitComponents(p string) []string {
	var out []string
	if strings.HasPrefix(p, "/") {
		out = append(out, "/")
	}
	for _, c := range strings.Split(p, "/") {
		if c != "" && c != "." {
			out = append(out, c)
		}
	}
	return out
}

func matchComponents(pat, comps []string) bool {
	for i := range pat {
		if ok, err := filepath.Match(pat[i], comps[i]); err != nil || !ok {
			return false
		}
	}
	return true
}

// ValidSensitivePattern reports whether every component of pattern is a
// well-formed glob.
func ValidSensitivePattern(pattern string) bool {
	if strings.TrimSpace(pattern) == "" {
		return false
	}
	for _, c := range splitComponents(pattern) {
		if _, err := filepath.Match(c, ""); err != nil {
			return false
		}
	}
	return true
}

func isSecretPath(p string) bool {
	for _, re := range secretPatterns {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}
