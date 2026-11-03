package argv

import (
	"reflect"
	"testing"

	"github.com/zhaozhaozz/shell-policy/internal/ir"
)

func arg(value string) ir.ArgValue {
	return ir.ArgValue{Raw: value, Value: value, Confidence: ir.ConfStatic}
}

func dyn(raw string) ir.ArgValue {
	return ir.ArgValue{Raw: raw, Confidence: ir.ConfDynamic}
}

func TestParseShortClustersLongFlagsAndDoubleDash(t *testing.T) {
	parsed := Parse([]ir.ArgValue{arg("rm"), arg("-rf"), arg("--"), arg("-literal")}, Spec{
		Flags: map[string]FlagSpec{
			"recursive": {Names: []string{"-r", "-R", "--recursive"}},
			"force":     {Names: []string{"-f", "--force"}},
		},
	})

	if parsed.Flags["recursive"] != true || parsed.Flags["force"] != true {
		t.Fatalf("expected -rf to set recursive and force flags, got %#v", parsed.Flags)
	}
	if got := values(parsed.Positionals); !reflect.DeepEqual(got, []string{"-literal"}) {
		t.Fatalf("positionals after -- should be retained, got %#v", got)
	}
	if got := values(parsed.AfterDoubleDash); !reflect.DeepEqual(got, []string{"-literal"}) {
		t.Fatalf("AfterDoubleDash should retain literal operands, got %#v", got)
	}
}

func TestParseValueFlagsRepeatableInlineAndAdjacent(t *testing.T) {
	parsed := Parse([]ir.ArgValue{
		arg("grep"), arg("-R"), arg("-efoo"), arg("--regexp=bar"), arg("-n"), arg("5"), arg("needle"), arg("src"),
	}, Spec{
		Flags: map[string]FlagSpec{
			"recursive": {Names: []string{"-r", "-R", "--recursive"}},
			"pattern":   {Names: []string{"-e", "--regexp"}, TakesValue: true, Repeatable: true},
			"lines":     {Names: []string{"-n", "--lines"}, TakesValue: true},
		},
	})

	if parsed.Flags["recursive"] != true {
		t.Fatalf("expected recursive flag, got %#v", parsed.Flags)
	}
	if got := parsed.Flags["pattern"]; !reflect.DeepEqual(got, []any{"foo", "bar"}) {
		t.Fatalf("expected repeated pattern values, got %#v", got)
	}
	if parsed.Flags["lines"] != "5" {
		t.Fatalf("expected -n value 5, got %#v", parsed.Flags["lines"])
	}
	if got := values(parsed.Positionals); !reflect.DeepEqual(got, []string{"needle", "src"}) {
		t.Fatalf("unexpected positionals: %#v", got)
	}
}

func TestParseStopAtFirstPositionalKeepsSubcommandArgs(t *testing.T) {
	parsed := Parse([]ir.ArgValue{
		arg("git"), arg("-C"), arg("repo"), arg("push"), arg("--force"), arg("origin"), arg("main"),
	}, Spec{
		StopAtFirstPositional: true,
		Flags: map[string]FlagSpec{
			"chdir": {Names: []string{"-C"}, TakesValue: true},
		},
	})

	if parsed.Flags["chdir"] != "repo" {
		t.Fatalf("expected git -C value, got %#v", parsed.Flags)
	}
	if got := values(parsed.Positionals); !reflect.DeepEqual(got, []string{"push", "--force", "origin", "main"}) {
		t.Fatalf("subcommand args should remain positional, got %#v", got)
	}
}

func TestParseDynamicArgumentMarksHasDynamic(t *testing.T) {
	parsed := Parse([]ir.ArgValue{arg("rm"), arg("-rf"), dyn("$TARGET")}, Spec{
		Flags: map[string]FlagSpec{
			"recursive": {Names: []string{"-r"}},
			"force":     {Names: []string{"-f"}},
		},
	})

	if !parsed.HasDynamic {
		t.Fatal("expected dynamic operand to mark parsed args as dynamic")
	}
	if got := values(parsed.Positionals); !reflect.DeepEqual(got, []string{""}) {
		t.Fatalf("dynamic positional should be preserved with empty static value, got %#v", got)
	}
}

func values(args []ir.ArgValue) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		out = append(out, arg.Value)
	}
	return out
}
