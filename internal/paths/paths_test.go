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
		{name: "glob", value: av("logs/*.txt"), wantKind: ir.PathGlob, wantScope: ir.ScopeUnknown},
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
