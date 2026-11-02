package analyze

import (
	"testing"

	"github.com/self/shell_permission/internal/ir"
	"github.com/self/shell_permission/internal/paths"
)

// rmTarget analyzes command (cwd /repo, HOME /home/alice) and returns the
// first path deleted by the last rm in it.
func rmTarget(t *testing.T, command string) ir.NormalizedPath {
	t.Helper()
	root := analyzeForTest(t, command)
	var rm *ir.Command
	for _, leaf := range ir.Leaves(root) {
		if leaf.Simple != nil && leaf.Simple.Program.Value == "rm" {
			rm = leaf
		}
	}
	if rm == nil {
		t.Fatalf("no rm leaf in %q", command)
	}
	del := requireOp(t, rm, ir.OpFileDelete)
	if len(del.Paths) == 0 {
		t.Fatalf("rm in %q has no paths", command)
	}
	return del.Paths[0]
}

func TestCdChangesWhereLaterPathsResolve(t *testing.T) {
	cases := []struct {
		command string
		want    string // absolute path; "" means the directory is unknown
	}{
		{`rm passwd`, "/repo/passwd"},
		{`cd /etc && rm -f passwd`, "/etc/passwd"},
		{`cd /etc && cd ssh && rm x`, "/etc/ssh/x"},
		{`cd sub && rm x`, "/repo/sub/x"},
		{`cd .. && rm x`, "/x"},
		{`cd && rm x`, "/home/alice/x"},
		{`cd ~/proj && rm x`, "/home/alice/proj/x"},
		{`cd -- /etc && rm x`, "/etc/x"},
		{`cd -P /etc && rm x`, "/etc/x"},
		{`pushd /etc && rm x`, "/etc/x"},
		{`pushd -n /etc && rm x`, "/repo/x"},
		{`command cd /etc && rm x`, "/etc/x"},
		{`builtin cd /etc && rm x`, "/etc/x"},
		// The target is not known statically.
		{`cd "$X" && rm x`, ""},
		{`cd /e* && rm x`, ""},
		{`cd - && rm x`, ""},
		{`cd ~bob && rm x`, ""},
		{`popd && rm x`, ""},
		{`pushd && rm x`, ""},
		{`pushd +1 && rm x`, ""},
		{`source env.sh && rm x`, ""},
		{`$CMD && rm x`, ""},
		// A cd that may have failed leaves the directory ambiguous.
		{`cd /etc; rm x`, ""},
		{`cd /etc || rm x`, "/repo/x"},
		{`cd /etc || true; rm x`, ""},
		{`cd /repo; rm x`, "/repo/x"},
		// Subshells, pipelines and background jobs do not move this shell.
		{`(cd /etc) && rm x`, "/repo/x"},
		{`(cd /etc && rm x)`, "/etc/x"},
		{`echo $(cd /etc) && rm x`, "/repo/x"},
		{`cd /etc & rm x`, "/repo/x"},
		{`cd /etc | cat && rm x`, "/repo/x"},
		{`cat | cd /etc && rm x`, ""}, // zsh runs the last element in this shell
		{`bash -c 'cd /etc' && rm x`, "/repo/x"},
		{`bash -c 'cd /etc && rm x'`, "/etc/x"},
		// Wrappers that start the command elsewhere.
		{`sudo -D /etc rm x`, "/etc/x"},
		{`sudo --chdir=/etc rm x`, "/etc/x"},
		{`sudo -n -u root rm x`, "/repo/x"},
		{`env -C /etc rm x`, "/etc/x"},
		{`find /etc -name x -execdir rm x \;`, ""},
		// Loops repeat their body, so a cd anywhere inside taints all of it.
		{`for i in 1 2; do rm x; cd /etc; done`, ""},
		{`if true; then cd /etc; fi; rm x`, ""},
		{`for i in 1 2; do rm x; done`, "/repo/x"},
	}
	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			got := rmTarget(t, tc.command)
			if got.Absolute != tc.want {
				t.Fatalf("rm target = %q (scope %s), want %q", got.Absolute, got.Scope, tc.want)
			}
			if tc.want == "" && got.Scope != ir.ScopeUnknown {
				t.Fatalf("unknown directory should give scope unknown, got %s", got.Scope)
			}
		})
	}
}

func TestUnknownCwdKeepsRelativePathsUnknown(t *testing.T) {
	r := &paths.Resolver{WorkspaceRoots: []string{"/repo"}, WritableRoots: []string{"/repo"}, Home: "/home/alice"}
	pr, err := AnalyzeText(`rm build/x && rm /repo/y && cat .env`, r)
	if err != nil {
		t.Fatal(err)
	}
	leaves := ir.Leaves(pr.Command)
	rel := leaves[0].Simple.Operations[0].Paths[0]
	if rel.Scope != ir.ScopeUnknown || rel.Writable {
		t.Fatalf("relative path with unknown cwd = %+v", rel)
	}
	abs := leaves[1].Simple.Operations[0].Paths[0]
	if abs.Scope != ir.ScopeInsideWorkspace || !abs.Writable {
		t.Fatalf("absolute path should still resolve: %+v", abs)
	}
	secret := leaves[2].Simple.Operations[0].Paths[0]
	if !secret.SecretCandidate {
		t.Fatalf("relative secret should still be flagged: %+v", secret)
	}
	if r.Cwd != "" {
		t.Fatalf("Analyze must restore the resolver cwd, got %q", r.Cwd)
	}
}

func TestAnalyzeRestoresResolverCwd(t *testing.T) {
	r := testResolver()
	if _, err := AnalyzeText(`cd /etc && rm x`, r); err != nil {
		t.Fatal(err)
	}
	if r.Cwd != "/repo" {
		t.Fatalf("resolver cwd changed to %q", r.Cwd)
	}
}
