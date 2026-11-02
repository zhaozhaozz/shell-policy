// Package paths provides path normalization and classification.
//
// Normalization is *static*: there is no filesystem access and no
// environment variable expansion. Dynamic tokens (those that contain
// $vars or unresolved parts) are flagged accordingly so policy can
// refuse to silently allow them.
package paths

import (
	"path/filepath"
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

// builtinSensitive is the built-in list of secret-like paths, in the
// sensitive-path syntax of MatchSensitive (unanchored, per component, a
// match covers everything below it). Keeping one syntax lets the glob check
// (GlobMayHit) reason about the built-in list and the user's patterns alike.
var builtinSensitive = []string{
	".env", ".env.*", ".ssh/", "id_rsa", "id_rsa.pub", "id_ed25519", "id_ed25519.pub",
	"*.pem", "*.key", "*.p12", ".kube/config", ".aws/credentials", ".gcp/", ".azure/",
	".npmrc", ".pypirc", ".netrc", "credentials", "credentials.json", "secret*",
	// Git's own config and hooks decide which programs later git commands
	// run (core.pager, hooks): writing them is not an ordinary edit.
	".git/config", ".git/hooks/",
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
		} else {
			// "cat *" names no secret, but can expand to demo.key.
			np.SecretPossible = r.globMayHitSecret(raw)
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

// globMayHitSecret reports whether the glob raw could expand to a path that
// a built-in or user sensitive pattern covers. The glob is anchored like a
// static path (~ and the working directory) when possible.
func (r *Resolver) globMayHitSecret(raw string) bool {
	g := raw
	switch {
	case (g == "~" || strings.HasPrefix(g, "~/")) && r.Home != "":
		g = filepath.Join(r.Home, strings.TrimPrefix(g, "~"))
	case !filepath.IsAbs(g) && !strings.HasPrefix(g, "~") && r.Cwd != "":
		g = filepath.Join(r.Cwd, g)
	}
	for _, pats := range [][]string{builtinSensitive, r.SensitivePaths} {
		for _, pat := range pats {
			if GlobMayHit(pat, g, r.Home) {
				return true
			}
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
	for _, pat := range builtinSensitive {
		if MatchSensitive(pat, p, "") {
			return true
		}
	}
	return false
}

// GlobMayHit reports whether some path the shell glob g can expand to is
// covered by the sensitive pattern (MatchSensitive syntax). Wildcards follow
// the shell: they never match a leading dot, and a "**" component (globstar)
// spans any number of non-hidden directories. Character classes are compared
// loosely, so the answer errs towards "may hit".
func GlobMayHit(pattern, g, home string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || g == "" {
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
	pc, gc := splitComponents(pattern), splitComponents(g)
	if len(pc) == 0 {
		return false
	}
	// hit(i, j): glob components gc[i:] can produce pattern components pc[j:]
	// in order; once the pattern is complete, anything below is covered.
	var hit func(i, j int) bool
	hit = func(i, j int) bool {
		if j == len(pc) {
			return true
		}
		if i == len(gc) {
			return false
		}
		if gc[i] == "**" {
			return hit(i+1, j) || !strings.HasPrefix(pc[j], ".") && hit(i, j+1)
		}
		return componentsMeet(pc[j], gc[i]) && hit(i+1, j+1)
	}
	if anchored {
		return hit(0, 0)
	}
	for start := range gc {
		if hit(start, 0) {
			return true
		}
	}
	return false
}

// componentsMeet reports whether one path component can match both the
// sensitive pattern component p and the glob component g.
func componentsMeet(p, g string) bool {
	if !containsGlob(g) {
		ok, err := filepath.Match(p, g)
		return err == nil && ok
	}
	if !strings.HasPrefix(g, ".") && strings.HasPrefix(p, ".") {
		return false // the shell's wildcards skip dot files
	}
	return globsMeet(globTokens(p), globTokens(g))
}

// globTok is one element of a glob: "*", "?", a [class] or a literal rune.
type globTok struct {
	star, any bool
	class     string // the inside of [...], "" for other kinds
	lit       rune
}

func globTokens(s string) []globTok {
	var out []globTok
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		switch c := rs[i]; c {
		case '*':
			if len(out) == 0 || !out[len(out)-1].star {
				out = append(out, globTok{star: true})
			}
		case '?':
			out = append(out, globTok{any: true})
		case '[':
			end := i + 1
			if end < len(rs) && (rs[end] == '!' || rs[end] == '^') {
				end++
			}
			if end < len(rs) && rs[end] == ']' {
				end++
			}
			for end < len(rs) && rs[end] != ']' {
				end++
			}
			if end >= len(rs) {
				out = append(out, globTok{lit: c})
				continue
			}
			out = append(out, globTok{class: string(rs[i+1 : end])})
			i = end
		case '\\':
			if i+1 < len(rs) {
				i++
			}
			out = append(out, globTok{lit: rs[i]})
		default:
			out = append(out, globTok{lit: c})
		}
	}
	return out
}

// globsMeet reports whether some string matches both token lists.
func globsMeet(a, b []globTok) bool {
	memo := map[[2]int]bool{}
	var meet func(i, j int) bool
	meet = func(i, j int) bool {
		key := [2]int{i, j}
		if v, ok := memo[key]; ok {
			return v
		}
		var ok bool
		switch {
		case i == len(a) && j == len(b):
			ok = true
		case i < len(a) && a[i].star && meet(i+1, j), j < len(b) && b[j].star && meet(i, j+1):
			ok = true
		case i < len(a) && j < len(b):
			switch {
			case a[i].star && b[j].star:
			case a[i].star:
				ok = meet(i, j+1) // a's star absorbs b's next character
			case b[j].star:
				ok = meet(i+1, j)
			default:
				ok = charsMeet(a[i], b[j]) && meet(i+1, j+1)
			}
		}
		memo[key] = ok
		return ok
	}
	return meet(0, 0)
}

func charsMeet(x, y globTok) bool {
	switch {
	case x.any || y.any, x.class != "" && y.class != "":
		return true
	case x.class != "":
		return classHas(x.class, y.lit)
	case y.class != "":
		return classHas(y.class, x.lit)
	}
	return x.lit == y.lit
}

func classHas(class string, r rune) bool {
	if strings.HasPrefix(class, "!") {
		class = "^" + class[1:]
	}
	ok, err := filepath.Match("["+class+"]", string(r))
	return err != nil || ok
}
