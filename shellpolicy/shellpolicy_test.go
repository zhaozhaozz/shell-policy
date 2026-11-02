package shellpolicy

import (
	"bytes"
	"strings"
	"testing"
)

const work = "/home/alice/project"

func env() Env {
	return Env{Cwd: work, Home: "/home/alice", WritableDirs: []string{work}}
}

func eval(t *testing.T, p *Policy, command string, e Env) *Result {
	t.Helper()
	res, err := p.Evaluate(command, e)
	if err != nil {
		t.Fatalf("Evaluate(%q): %v", command, err)
	}
	return res
}

func TestEvaluateDefaultPolicy(t *testing.T) {
	p := Default()
	cases := []struct {
		command string
		effect  Effect
		action  string
	}{
		{`sudo ls`, Ask, "ask_privilege"},
		{`rm build/x`, Allow, "allow"},
		{`cat .env`, Ask, "ask_sensitive_read"},
		{`cd /etc && rm -f passwd`, Ask, "ask_write_outside_writable"},
		{`cat README.md > ~/.bashrc`, Ask, "ask_write_outside_writable"},
		{`cd src && ls`, Allow, "allow_readonly"},
		{`make`, Ask, "default"},
		{`rm -rf /`, Deny, "deny_destructive"},
	}
	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			res := eval(t, p, tc.command, env())
			if res.Effect != tc.effect || res.Action != tc.action {
				t.Fatalf("got %s/%s (%s), want %s/%s; steps=%+v", res.Effect, res.Action, res.Reason, tc.effect, tc.action, res.Steps)
			}
		})
	}
}

func TestEvaluateReportsTrace(t *testing.T) {
	res := eval(t, Default(), `cat README.md > ~/.bashrc`, env())
	if res.RuleID != "ask-write-outside-writable" {
		t.Fatalf("rule = %q", res.RuleID)
	}
	var partial bool
	for _, s := range res.Steps {
		if s.RuleID == "allow-bash-readonly" && s.Partial && s.Command == "cat README.md > ~/.bashrc" {
			partial = true
		}
	}
	if !partial {
		t.Fatalf("expected a partial allow step, got %+v", res.Steps)
	}
	if len(res.Operations) != 2 || res.Operations[1].Paths[0].Absolute != "/home/alice/.bashrc" {
		t.Fatalf("operations = %+v", res.Operations)
	}
	res = eval(t, Default(), `make`, env())
	if res.RuleID != "" || res.Action != "default" {
		t.Fatalf("default decision should have no rule: %+v", res)
	}
}

func TestEnvIsPerCall(t *testing.T) {
	p := Default()
	a := Env{Cwd: "/srv/a", WritableDirs: []string{"/srv/a"}}
	b := Env{Cwd: "/srv/b", WritableDirs: []string{"/srv/b"}}
	if res := eval(t, p, `rm /srv/a/x`, a); res.Effect != Allow {
		t.Fatalf("a should allow its own dir: %+v", res)
	}
	if res := eval(t, p, `rm /srv/a/x`, b); res.Effect != Ask {
		t.Fatalf("b must not see a's whitelist: %+v", res)
	}
	// Unknown working directory: relative targets are never writable.
	if res := eval(t, p, `rm x`, Env{WritableDirs: []string{"/srv/a"}}); res.Effect != Ask {
		t.Fatalf("relative path with unknown cwd should ask: %+v", res)
	}
	// Extra sensitive paths.
	e := env()
	e.SensitivePaths = []string{"*.sqlite"}
	if res := eval(t, p, `cat data/app.sqlite`, e); res.Action != "ask_sensitive_read" {
		t.Fatalf("sensitive pattern ignored: %+v", res)
	}
}

func TestWithEffects(t *testing.T) {
	base := Default()
	deny, err := base.WithEffects(map[string]Effect{"ask_privilege": Deny, "ask_network": Deny})
	if err != nil {
		t.Fatal(err)
	}
	if res := eval(t, deny, `sudo ls`, env()); res.Effect != Deny || res.Action != "ask_privilege" {
		t.Fatalf("privilege=deny: %+v", res)
	}
	// A category set to deny wins over another category that asks.
	if res := eval(t, deny, `curl -o /etc/x https://example.com`, env()); res.Effect != Deny {
		t.Fatalf("network=deny with an outside write: %+v", res)
	}
	// The original policy is unchanged.
	if res := eval(t, base, `sudo ls`, env()); res.Effect != Ask {
		t.Fatalf("base policy changed: %+v", res)
	}

	// Allowing a category stops it asking; other rules still decide.
	allow, err := base.WithEffects(map[string]Effect{"ask_privilege": Allow})
	if err != nil {
		t.Fatal(err)
	}
	if res := eval(t, allow, `sudo make`, env()); res.Action != "default" {
		t.Fatalf("privilege=allow should fall through to default: %+v", res)
	}
	if res := eval(t, allow, `sudo rm /etc/x`, env()); res.Action != "ask_write_outside_writable" {
		t.Fatalf("privilege=allow must not allow the inner write: %+v", res)
	}

	// The default action is set literally and only applies to undecided commands.
	def, err := base.WithEffects(map[string]Effect{"default": Deny})
	if err != nil {
		t.Fatal(err)
	}
	if res := eval(t, def, `make`, env()); res.Effect != Deny {
		t.Fatalf("default=deny: %+v", res)
	}
	if res := eval(t, def, `curl https://example.com`, env()); res.Effect != Ask {
		t.Fatalf("default=deny must not change categories: %+v", res)
	}
	open, err := base.WithEffects(map[string]Effect{"default": Allow})
	if err != nil {
		t.Fatal(err)
	}
	if res := eval(t, open, `make && cat /etc/hosts`, env()); res.Effect != Allow {
		t.Fatalf("default=allow: %+v", res)
	}
	if res := eval(t, open, `cd /etc && rm -f passwd`, env()); res.Effect != Ask {
		t.Fatalf("default=allow must keep outside writes asking: %+v", res)
	}

	if _, err := base.WithEffects(map[string]Effect{"nope": Ask}); err == nil {
		t.Fatal("unknown action should fail")
	}
	if _, err := base.WithEffects(map[string]Effect{"ask_network": "maybe"}); err == nil {
		t.Fatal("invalid effect should fail")
	}
}

func TestParseErrors(t *testing.T) {
	for yaml, want := range map[string]string{
		"policy: [": "yaml",
		"policy:\n  id: p\n  defaultAcion: ask\n":                                                            "defaultAcion",
		"policy:\n  id: p\nrules:\n  - id: r\n    match: {command.prog: ls}\n    action: ask\n":              "unknown field",
		"policy:\n  id: p\nrules:\n  - id: r\n    match: {command.program: {regex: '('}}\n    action: ask\n": "regex",
		"policy:\n  id: p\nrules:\n  - id: r\n    match: {}\n    action: nope\n":                             "unknown action",
	} {
		_, err := Parse([]byte(yaml))
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
			t.Errorf("Parse(%q) error = %v, want mention of %q", yaml, err, want)
		}
	}
	if _, err := Default().Evaluate(`if then`, env()); err == nil {
		t.Fatal("a parse error should be returned")
	}
}

func TestDefaultActions(t *testing.T) {
	p := Default()
	if p.DefaultAction() != "default" {
		t.Fatalf("default action = %q", p.DefaultAction())
	}
	for _, name := range []string{"ask_privilege", "ask_write_outside_writable", "deny_destructive", "ask_sensitive_read",
		"deny_secret_exfiltration", "ask_network", "ask_remote", "ask_package_manager", "deny_inline_eval", "default"} {
		a, ok := p.Action(name)
		if !ok {
			t.Fatalf("missing action %s", name)
		}
		if name != "default" && a.Rules == 0 {
			t.Fatalf("action %s has no rules", name)
		}
	}
}

func TestValidSensitivePattern(t *testing.T) {
	if !ValidSensitivePattern("~/.aws/") || ValidSensitivePattern("[") || ValidSensitivePattern("") {
		t.Fatal("ValidSensitivePattern mismatch")
	}
}

func TestAuthoringGuide(t *testing.T) {
	g := AuthoringGuide()
	if !bytes.HasPrefix(g, []byte("# ")) || !bytes.Contains(g, []byte("rules:")) {
		t.Fatalf("authoring guide not embedded: %.40q", g)
	}
	g[0] = 'x' // callers get a copy
	if AuthoringGuide()[0] != '#' {
		t.Fatal("AuthoringGuide must return a copy")
	}
}

// TestReadOnlyNeedsProof covers commands that look read-only by program or
// subcommand but write, delete or run other programs: they must not be
// auto-allowed, while the genuinely read-only forms still are.
func TestReadOnlyNeedsProof(t *testing.T) {
	p := Default()
	// Reads inside the workspace are allowed; nothing is writable, so a
	// command recognized as a write or an exec is not auto-allowed.
	e := Env{Cwd: work, Home: "/home/alice", WorkspaceRoots: []string{work}}
	notAllowed := []string{
		"git config --global core.editor vim", "git config core.pager less", "git branch -D main", "git branch newname",
		"git tag -d v1", "git tag v2", "git stash clear", "git stash", "git remote add o https://x",
		"git -c core.pager='touch /x' log", "git diff --output=/etc/x", "git log --output /tmp/x",
		"git grep -O vim foo", "docker image rm example:latest", "docker image prune -af",
		"docker container rm c1", "docker system prune -f", "rg --pre 'touch /x' token README.md",
		"GIT_PAGER='touch /x' git log", "PAGER='touch /x' git log", "GIT_EXTERNAL_DIFF=/tmp/x git diff",
		"RIPGREP_CONFIG_PATH=/tmp/cfg rg foo README.md", "GIT_CONFIG_COUNT=1 git log", "LC_ALL=C grep foo README.md",
	}
	for _, c := range notAllowed {
		if res := eval(t, p, c, e); res.Effect == Allow {
			t.Errorf("%q must not be auto-allowed: %s/%s (%s)", c, res.Effect, res.Action, res.RuleID)
		}
	}
	allowed := []string{
		"git status", "git log --oneline -5", "git diff HEAD~1", "git branch", "git branch -a", "git branch --contains abc",
		"git tag", "git tag -l 'v*'", "git stash list", "git stash show -p", "git config user.name",
		"git config --get user.email", "git config --list", "git remote -v", "git reflog",
		"docker ps -a", "docker image ls", "docker container inspect c1", "docker system df", "rg foo README.md",
	}
	for _, c := range allowed {
		if res := eval(t, p, c, e); res.Effect != Allow {
			t.Errorf("%q should stay allowed: %s/%s (%s)", c, res.Effect, res.Action, res.Reason)
		}
	}
	// With the repository writable, ordinary git writes are allowed like any
	// write there, but not .git/config or hooks, which decide what later git
	// commands run, nor a global config write in HOME.
	w := Env{Cwd: work, Home: "/home/alice", WritableDirs: []string{work}}
	for c, want := range map[string]Effect{
		"git branch -D main":               Allow,
		"git commit -m x":                  Allow,
		"git config user.name alice":       Ask,
		"git config core.pager 'touch /x'": Ask,
		"echo x > .git/hooks/pre-commit":   Ask,
		"git config --global user.name x":  Ask,
	} {
		if res := eval(t, p, c, w); res.Effect != want {
			t.Errorf("%q in a writable repo: %s/%s, want %s", c, res.Effect, res.Action, want)
		}
	}
}
