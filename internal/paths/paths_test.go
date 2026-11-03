package paths

import (
	"testing"

	"github.com/zhaozhaozz/shell-policy/internal/ir"
)

func TestResolverClassifiesCommonPathShapes(t *testing.T) {
	resolver := &Resolver{Cwd: "/work/project", WorkspaceRoots: []string{"/work/project"}, Home: "/home/alice"}

	cases := []struct {
		name       string
		value      ir.ArgValue
		wantKind   ir.PathKind
		wantScope  ir.PathScope
		wantSecret bool
	}{
		{name: "workspace relative", value: av("src/main.go"), wantKind: ir.PathWorkspaceRelative, wantScope: ir.ScopeInsideWorkspace},
		{name: "home secret", value: av("~/.ssh/id_rsa"), wantKind: ir.PathHomeRelative, wantScope: ir.ScopeSecretCandidate, wantSecret: true},
		{name: "system", value: av("/etc/passwd"), wantKind: ir.PathAbsolute, wantScope: ir.ScopeSystem},
		{name: "tmp", value: av("/tmp/out.txt"), wantKind: ir.PathAbsolute, wantScope: ir.ScopeTmp},
		{name: "secret basename", value: av(".env.local"), wantKind: ir.PathWorkspaceRelative, wantScope: ir.ScopeSecretCandidate, wantSecret: true},
		{name: "glob", value: av("logs/*.txt"), wantKind: ir.PathGlob, wantScope: ir.ScopeInsideWorkspace},
		{name: "stdin dash", value: av("-"), wantKind: ir.PathStdinDash, wantScope: ir.ScopeStdin},
		{name: "dynamic", value: ir.ArgValue{Raw: "$TARGET", Confidence: ir.ConfDynamic}, wantKind: ir.PathDynamic, wantScope: ir.ScopeUnknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolver.Resolve(tc.value)
			if got.Kind != tc.wantKind || got.Scope != tc.wantScope || got.SecretCandidate != tc.wantSecret {
				t.Fatalf("Resolve(%q) kind/scope/secret = %s/%s/%v, want %s/%s/%v", tc.value.Raw, got.Kind, got.Scope, got.SecretCandidate, tc.wantKind, tc.wantScope, tc.wantSecret)
			}
		})
	}
}

func av(value string) ir.ArgValue {
	return ir.ArgValue{Raw: value, Value: value, Confidence: ir.ConfStatic}
}

// TestResolverClassifiesGlobByStaticPrefix verifies that a glob path keeps
// PathGlob kind but takes its scope from the static directory prefix, so a
// dangerous glob over a system directory is not silently downgraded to
// "unknown".
func TestResolverClassifiesGlobByStaticPrefix(t *testing.T) {
	resolver := &Resolver{Cwd: "/work/project", WorkspaceRoots: []string{"/work/project"}, Home: "/home/alice"}

	cases := []struct {
		name      string
		raw       string
		wantScope ir.PathScope
	}{
		{"system glob", "/var/log/*", ir.ScopeSystem},
		{"etc glob", "/etc/*.conf", ir.ScopeSystem},
		{"workspace glob", "build/**", ir.ScopeInsideWorkspace},
		{"home glob", "~/.config/*", ir.ScopeHome},
		{"tmp glob", "/tmp/*", ir.ScopeTmp},
		{"leading glob anchors to cwd", "*.go", ir.ScopeInsideWorkspace},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolver.Resolve(av(tc.raw))
			if got.Kind != ir.PathGlob {
				t.Fatalf("Resolve(%q) kind = %s, want %s", tc.raw, got.Kind, ir.PathGlob)
			}
			if got.Scope != tc.wantScope {
				t.Fatalf("Resolve(%q) scope = %s, want %s", tc.raw, got.Scope, tc.wantScope)
			}
		})
	}
}

func TestResolverMarksWritableDirs(t *testing.T) {
	resolver := &Resolver{
		Cwd:            "/work/project",
		WorkspaceRoots: []string{"/work/project"},
		Home:           "/home/alice",
		WritableRoots:  []string{"/work/project/build", "/work/project/.cache"},
	}

	cases := []struct {
		name         string
		value        ir.ArgValue
		wantWritable bool
	}{
		{name: "inside writable root", value: av("build/app.bin"), wantWritable: true},
		{name: "writable root itself", value: av("build"), wantWritable: true},
		{name: "second writable root", value: av(".cache/x"), wantWritable: true},
		{name: "outside writable root", value: av("src/main.go"), wantWritable: false},
		{name: "absolute writable", value: av("/work/project/build/out"), wantWritable: true},
		{name: "writable prefix sibling not matched", value: av("build-extra/x"), wantWritable: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolver.Resolve(tc.value)
			if got.Writable != tc.wantWritable {
				t.Fatalf("Resolve(%q).Writable = %v, want %v (abs=%s)", tc.value.Raw, got.Writable, tc.wantWritable, got.Absolute)
			}
		})
	}
}

func TestResolverNoWritableRootsMeansNothingWritable(t *testing.T) {
	resolver := &Resolver{Cwd: "/work/project", WorkspaceRoots: []string{"/work/project"}}
	got := resolver.Resolve(av("build/app.bin"))
	if got.Writable {
		t.Fatalf("expected no path to be writable when WritableRoots is empty")
	}
}

func TestMatchSensitive(t *testing.T) {
	cases := []struct {
		pattern, path, home string
		want                bool
	}{
		{"~/.aws/", "/home/alice/.aws/credentials", "/home/alice", true},
		{"~/.aws/", "/home/alice/.aws", "/home/alice", true},
		{"~/.aws/", "/srv/.aws/credentials", "/home/alice", false},
		{"~/.aws/", "~/.aws/config", "", true},
		{"~/.kube/config", "/home/alice/.kube/config", "/home/alice", true},
		{"~/.kube/config", "/home/alice/.kube/cache", "/home/alice", false},
		{"/etc/app/secrets/", "/etc/app/secrets/db.yml", "", true},
		{"/etc/app/secrets/", "/opt/etc/app/secrets/db.yml", "", false},
		{".env", "/repo/.env", "", true},
		{".env", "/repo/.env/x", "", true},
		{".env", "/repo/.envrc", "", false},
		{".env.*", "/repo/.env.local", "", true},
		{"*.pem", "/repo/certs/server.pem", "", true},
		{"*.pem", "certs/server.pem", "", true},
		{"config/secrets.yml", "/repo/config/secrets.yml", "", true},
		{"config/secrets.yml", "/repo/secrets.yml", "", false},
		{"*.key", "/repo/keys", "", false},
	}
	for _, tc := range cases {
		if got := MatchSensitive(tc.pattern, tc.path, tc.home); got != tc.want {
			t.Errorf("MatchSensitive(%q, %q, %q) = %v, want %v", tc.pattern, tc.path, tc.home, got, tc.want)
		}
	}
}

func TestResolverSensitivePaths(t *testing.T) {
	r := &Resolver{Cwd: "/work/project", WorkspaceRoots: []string{"/work/project"}, Home: "/home/alice",
		SensitivePaths: []string{"~/.config/gh/", "*.sqlite", "deploy/vars.yml"}}
	for _, raw := range []string{"~/.config/gh/hosts.yml", "data/app.sqlite", "deploy/vars.yml", "/home/alice/.config/gh/*"} {
		if got := r.ResolveString(raw); !got.SecretCandidate || got.Scope != ir.ScopeSecretCandidate {
			t.Errorf("%s should be sensitive: %+v", raw, got)
		}
	}
	if got := r.ResolveString("data/app.db"); got.SecretCandidate {
		t.Errorf("data/app.db should not be sensitive")
	}
	if ValidSensitivePattern("[") || !ValidSensitivePattern("~/.aws/") || ValidSensitivePattern(" ") {
		t.Error("ValidSensitivePattern mismatch")
	}
}

func TestGlobMayHit(t *testing.T) {
	cases := []struct {
		pattern, glob string
		want          bool
	}{
		{"*.key", "/repo/*", true},            // cat * may read demo.key
		{".env", "/repo/*", false},            // * skips dot files
		{".env", "/repo/.*", true},            // .* does not
		{".env.*", "/repo/.e*", true},         //
		{"*.key", "/repo/*.md", false},        // literal suffixes differ
		{"secret*", "/repo/*.md", true},       // secrets.md
		{"id_rsa", "/home/u/.ssh/id_*", true}, //
		{".ssh/", "/home/u/*/id_rsa", false},  // * cannot be .ssh
		{".ssh/", "/home/u/.*/id_rsa", true},  //
		{".ssh/", "/home/u/.s?h/x", true},     //
		{"*.pem", "/repo/**/*.pem", true},     //
		{"*.pem", "/repo/src/*.go", false},    //
		{".git/hooks/", "/repo/.git/*", true}, // a hook under .git/hooks is hit via the dir component
		{".kube/config", "/home/u/.kube/c*", true},
		{"*.sqlite", "/data/*.[sd]*", true},   // user pattern, char class
		{"*.sqlite", "/data/[xy]*.db", false}, //
		{"/etc/app/secrets/", "/etc/app/*/token", true},
		{"/etc/app/secrets/", "/srv/*/token", false}, // anchored elsewhere
		{"~/.aws/", "/home/u/.aws/*", true},
	}
	for _, c := range cases {
		if got := GlobMayHit(c.pattern, c.glob, "/home/u"); got != c.want {
			t.Errorf("GlobMayHit(%q, %q) = %v, want %v", c.pattern, c.glob, got, c.want)
		}
	}
	r := &Resolver{Cwd: "/repo", Home: "/home/u", WorkspaceRoots: []string{"/repo"}}
	for raw, want := range map[string]bool{"*": true, "*.go": true, "docs/*.png": true, "*.[ch]": true, "src/main.[ch]": false, "README.md": false} {
		if got := r.ResolveString(raw).SecretPossible; got != want {
			t.Errorf("Resolve(%q).SecretPossible = %v, want %v", raw, got, want)
		}
	}
	if np := r.ResolveString("*.key"); !np.SecretCandidate || np.SecretPossible {
		t.Errorf("*.key names a secret outright: %+v", np)
	}
}
