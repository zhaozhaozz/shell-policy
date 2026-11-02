package parser

import (
	"reflect"
	"testing"

	"github.com/self/shell_permission/internal/ir"
)

func TestParsePipelineWithNestedSubstitutionsAndRedirect(t *testing.T) {
	pr, err := Parse(`cat input.txt | grep "x$(printf y)" <(cat names.txt) > out.txt`)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if pr.Command.Kind != ir.KindPipeline {
		t.Fatalf("root kind = %s, want pipeline", pr.Command.Kind)
	}
	if len(pr.Command.Children) != 2 {
		t.Fatalf("pipeline children = %d, want 2", len(pr.Command.Children))
	}
	for _, child := range pr.Command.Children {
		if !child.Context.InPipeline {
			t.Fatalf("pipeline child %s did not inherit InPipeline context", child.ID)
		}
	}

	grep := pr.Command.Children[1]
	if grep.Simple == nil || grep.Simple.Program.Value != "grep" {
		t.Fatalf("second pipeline child should be grep, got %#v", grep.Simple)
	}
	if len(grep.Redirects) != 1 || grep.Redirects[0].Op != ir.RedirOut || grep.Redirects[0].Target.Value != "out.txt" {
		t.Fatalf("grep redirect mismatch: %#v", grep.Redirects)
	}
	if got := childKinds(grep); !reflect.DeepEqual(got, []ir.Kind{ir.KindCommandSubstitution, ir.KindProcessSubstitution}) {
		t.Fatalf("nested substitution kinds = %#v", got)
	}
}

func TestParseControlFlowAuditsAllBranches(t *testing.T) {
	pr, err := Parse(`if test -f a; then rm -rf build; else git status; fi`)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if pr.Command.Kind != ir.KindControlFlow {
		t.Fatalf("root kind = %s, want control_flow", pr.Command.Kind)
	}
	if got := simplePrograms(pr.Command); !reflect.DeepEqual(got, []string{"test", "rm", "git"}) {
		t.Fatalf("control flow simple programs = %#v", got)
	}
}

func TestParseBackgroundAndSubshellContext(t *testing.T) {
	t.Run("background", func(t *testing.T) {
		pr, err := Parse(`sleep 1 &`)
		if err != nil {
			t.Fatalf("Parse returned error: %v", err)
		}
		if !pr.Command.Context.Background {
			t.Fatal("background statement should set Background context")
		}
	})

	t.Run("subshell", func(t *testing.T) {
		pr, err := Parse(`(cd /tmp; rm -f x)`)
		if err != nil {
			t.Fatalf("Parse returned error: %v", err)
		}
		if pr.Command.Kind != ir.KindSubshell {
			t.Fatalf("root kind = %s, want subshell", pr.Command.Kind)
		}
		for _, leaf := range parserLeaves(pr.Command) {
			if !leaf.Context.InSubshell {
				t.Fatalf("subshell leaf %q missing InSubshell context", leaf.Simple.Program.Value)
			}
		}
	})
}

func TestParseErrorReportsStructuredPosition(t *testing.T) {
	pr, err := Parse(`if true; then echo ok`)
	if err == nil {
		t.Fatal("expected parse error")
	}
	if len(pr.Errors) != 1 || pr.Errors[0].Line == 0 || pr.Errors[0].Col == 0 || pr.Errors[0].Message == "" {
		t.Fatalf("parse errors not populated: %#v", pr.Errors)
	}
}

func childKinds(c *ir.Command) []ir.Kind {
	out := make([]ir.Kind, 0, len(c.Children))
	for _, child := range c.Children {
		out = append(out, child.Kind)
	}
	return out
}

func simplePrograms(c *ir.Command) []string {
	out := []string{}
	ir.Walk(c, func(n *ir.Command) {
		if n.Kind == ir.KindSimple && n.Simple != nil {
			out = append(out, n.Simple.Program.Value)
		}
	})
	return out
}

func parserLeaves(c *ir.Command) []*ir.Command {
	out := []*ir.Command{}
	ir.Walk(c, func(n *ir.Command) {
		if n.Kind == ir.KindSimple && n.Simple != nil {
			out = append(out, n)
		}
	})
	return out
}

// TestParseExposesHiddenCommands checks that commands nested in keywords,
// declarations, assignments and redirect targets become IR leaves.
func TestParseExposesHiddenCommands(t *testing.T) {
	cases := []struct {
		command string
		want    []string
	}{
		{`time rm -rf x`, []string{"rm"}},
		{`export X=$(rm a) Y=1`, []string{"export", "rm"}},
		{`local -r X="$(rm a)"`, []string{"local", "rm"}},
		{`X=$(rm a) ls`, []string{"ls", "rm"}},
		{`Y=${Z:-$(rm a)}`, []string{"", "rm"}},
		{`cat > "$(rm a)"`, []string{"cat", "rm"}},
		{`(cd x) > "$(rm a)"`, []string{"rm", "cd"}},
		{`[[ -n $(rm a) ]]`, []string{"[[", "rm"}},
		{`(( $(rm a) + 1 ))`, []string{"((", "rm"}},
		{`coproc rm a`, []string{"rm"}},
		{`f() { rm a; }`, []string{"rm"}},
	}
	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			pr, err := Parse(tc.command)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := simplePrograms(pr.Command); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("programs = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestParseDeclarationWords(t *testing.T) {
	pr, err := Parse(`export -x PATH=/tmp:$PATH FOO`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range pr.Command.Simple.Argv {
		got = append(got, a.Value)
	}
	want := []string{"export", "-x", "PATH=/tmp:", "FOO"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
}

func TestParseUnescapesWords(t *testing.T) {
	cases := map[string]string{
		`rm foo\ bar`:       "foo bar",
		`find . -exec x \;`: ";",
		`echo "a\"b\$c\d"`:  `a"b$c\d`,
		`echo 'a\b'`:        `a\b`,
	}
	for command, want := range cases {
		pr, err := Parse(command)
		if err != nil {
			t.Fatal(err)
		}
		argv := pr.Command.Simple.Argv
		if got := argv[len(argv)-1].Value; got != want {
			t.Fatalf("%s: last word = %q, want %q", command, got, want)
		}
	}
}
