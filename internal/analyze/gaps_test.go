package analyze

import (
	"testing"

	"github.com/zhaozhaozz/shell-policy/internal/ir"
)

func leafNamed(t *testing.T, root *ir.Command, program string) *ir.Command {
	t.Helper()
	return requireProgram(t, root, program)
}

func TestFindPlaceholderResolvesUnderSearchRoots(t *testing.T) {
	root := analyzeForTest(t, `find build -name '*.o' -exec rm {} \;`)
	del := requireOp(t, leafNamed(t, root, "rm"), ir.OpFileDelete)
	if len(del.Paths) != 1 || del.Paths[0].Kind != ir.PathGlob || del.Paths[0].Scope != ir.ScopeInsideWorkspace {
		t.Fatalf("rm {} should target build/*: %+v", del.Paths)
	}
	root = analyzeForTest(t, `find /etc -name x -exec rm {} +`)
	del = requireOp(t, leafNamed(t, root, "rm"), ir.OpFileDelete)
	if del.Paths[0].Scope != ir.ScopeSystem {
		t.Fatalf("rm {} under /etc should be system scope: %+v", del.Paths)
	}
	root = analyzeForTest(t, `find build -exec mv {} {}.bak \;`)
	if !leafNamed(t, root, "mv").Simple.HasDynamicArgs {
		t.Fatal("an embedded {} is only known at run time")
	}
}

func TestXargsArgumentsFromStdinAreDynamic(t *testing.T) {
	for _, cmd := range []string{`ls | xargs rm`, `ls | xargs rm -f build/x`, `ls | xargs -I{} rm {}`, `ls | xargs -i rm {}`, `ls | xargs -I % rm %`} {
		root := analyzeForTest(t, cmd)
		if !leafNamed(t, root, "rm").Simple.HasDynamicArgs {
			t.Fatalf("%s: rm targets come from stdin and must be dynamic", cmd)
		}
	}
	// Options of the inner command are not mistaken for xargs options.
	root := analyzeForTest(t, `ls | xargs grep -n foo`)
	grep := leafNamed(t, root, "grep")
	if grep.Simple.Argv[1].Value != "-n" {
		t.Fatalf("grep argv = %+v", grep.Simple.Argv)
	}
}

func TestPrivilegeWrappers(t *testing.T) {
	for _, cmd := range []string{`doas rm x`, `pkexec rm x`, `su -c 'rm x' root`, `sudo -n rm x`} {
		root := analyzeForTest(t, cmd)
		if !leafNamed(t, root, "rm").Context.PrivilegeEscalated {
			t.Fatalf("%s: inner rm should run with elevated privileges", cmd)
		}
	}
}

func TestEvalStaticTextIsAnalyzed(t *testing.T) {
	root := analyzeForTest(t, `eval "rm x"`)
	requireOp(t, leafNamed(t, root, "rm"), ir.OpFileDelete)
	root = analyzeForTest(t, `eval "$X"`)
	if requireProgram(t, root, "eval").Simple.Wrapper != nil {
		t.Fatal("dynamic eval cannot be unwrapped")
	}
}

func TestFunctionBodiesAreAnalyzed(t *testing.T) {
	root := analyzeForTest(t, `f() { rm -rf ~; }; f`)
	rm := leafNamed(t, root, "rm")
	if !rm.Context.InFunction {
		t.Fatal("function body commands should be marked InFunction")
	}
	if leafNamed(t, root, "f").Context.InFunction {
		t.Fatal("the call itself is not inside the function")
	}
}

func TestShellConfigOperations(t *testing.T) {
	cases := []struct {
		command, program string
		config           bool
	}{
		{`export PATH=/tmp/x:$PATH`, "export", true},
		{`export CDPATH=/etc`, "export", true},
		{`declare -x LD_PRELOAD=/tmp/x.so`, "declare", true},
		{`unset PROMPT_COMMAND`, "unset", true},
		{`export "$NAME=1"`, "export", true},
		{`export FOO=1 BAR`, "export", false},
		{`PATH=/tmp/x ls`, "ls", true},
		{`HOME=/etc`, "", true},
		{`FOO=1`, "", false},
		{`alias ll='ls -l'`, "alias", true},
		{`alias`, "alias", false},
		{`trap 'rm -rf ~' EXIT`, "trap", true},
		{`trap -p`, "trap", false},
		{`hash -p /tmp/x ls`, "hash", true},
	}
	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			root := analyzeForTest(t, tc.command)
			leaf := ir.Leaves(root)[0]
			if leaf.Simple.Program.Value != tc.program {
				t.Fatalf("program = %q", leaf.Simple.Program.Value)
			}
			got := len(opsOfType(leaf, ir.OpShellConfig)) > 0
			if got != tc.config {
				t.Fatalf("shell_config = %v, want %v; ops=%+v", got, tc.config, leaf.Simple.Operations)
			}
		})
	}
}

func TestBuiltinsHaveNoOperations(t *testing.T) {
	for _, cmd := range []string{`pwd`, `cd /etc`, `true`, `:`, `echo hi`, `export FOO=1`, `test -f x`} {
		root := analyzeForTest(t, cmd)
		if ops := ir.Leaves(root)[0].Simple.Operations; len(ops) != 0 {
			t.Fatalf("%s: ops = %+v", cmd, ops)
		}
	}
}

func TestPackageManagers(t *testing.T) {
	cases := []struct {
		command string
		install bool
	}{
		{`apt-get -y install curl`, true},
		{`apt update`, true},
		{`pip install requests`, true},
		{`npm i left-pad`, true},
		{`yarn`, true},
		{`npx cowsay hi`, true},
		{`pacman -Syu`, true},
		{`rpm -ivh x.rpm`, true},
		{`go install example.com/x@latest`, true},
		{`npm run build`, false},
		{`go build ./...`, false},
		{`apt list --installed`, false},
		{`rpm -qa`, false},
	}
	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			leaf := ir.Leaves(analyzeForTest(t, tc.command))[0]
			got := len(opsOfType(leaf, ir.OpPackageInstall)) > 0
			if got != tc.install {
				t.Fatalf("package_install = %v, want %v; ops=%+v", got, tc.install, leaf.Simple.Operations)
			}
		})
	}
}

func TestDdOperands(t *testing.T) {
	leaf := leafNamed(t, analyzeForTest(t, `dd if=/dev/zero of=/dev/sda bs=1M`), "dd")
	w := requireOp(t, leaf, ir.OpFileWrite)
	if w.Paths[0].Absolute != "/dev/sda" {
		t.Fatalf("dd of= path = %+v", w.Paths)
	}
	r := requireOp(t, leaf, ir.OpFileRead)
	if r.Paths[0].Absolute != "/dev/zero" {
		t.Fatalf("dd if= path = %+v", r.Paths)
	}
}
