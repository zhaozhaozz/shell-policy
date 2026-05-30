package paths

import (
	"testing"

	"github.com/self/shell_permission/internal/ir"
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
