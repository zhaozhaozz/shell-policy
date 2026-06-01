// shell-policy is the CLI entry point. It exposes three sub-commands:
//
//	parse    -- show the IR tree for a command (debugging)
//	analyze  -- run parser + analyzer and dump operations
//	eval     -- run a policy against a command and print the decision
//	explain  -- like eval but verbose, includes the rule trace
//
// Exit codes match the design in plan.md:
//
//	0  allow
//	10 ask
//	20 deny
//	30 parse error
//	40 policy error
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/self/shell_permission/internal/analyze"
	"github.com/self/shell_permission/internal/audit"
	"github.com/self/shell_permission/internal/claudehook"
	"github.com/self/shell_permission/internal/parser"
	"github.com/self/shell_permission/internal/paths"
	"github.com/self/shell_permission/internal/policy"
)

func main() {
	if len(os.Args) < 2 {
		printUsage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "parse":
		os.Exit(cmdParse(os.Args[2:]))
	case "analyze":
		os.Exit(cmdAnalyze(os.Args[2:]))
	case "eval":
		os.Exit(cmdEval(os.Args[2:], false))
	case "explain":
		os.Exit(cmdEval(os.Args[2:], true))
	case "claude-hook":
		os.Exit(cmdClaudeHook(os.Args[2:]))
	case "-h", "--help", "help":
		printUsage(os.Stdout)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		printUsage(os.Stderr)
		os.Exit(2)
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `shell-policy <command> [flags] -- "<shell command>"

Commands:
  parse     Parse a shell command and print its IR.
  analyze   Parse, run wrapper detection and resource-op extraction.
  eval      Evaluate a policy against the command. Exit code reflects decision.
  explain   Like eval but emits the full per-leaf rule trace.
  claude-hook  Act as a Claude Code PreToolUse hook: read the hook JSON on
               stdin and emit a permission decision on stdout.

Common flags:
  --policy <file>          Path to policy YAML (default: policies/default.yaml).
  --cwd <path>             Working directory for path normalization (default: $PWD).
  --workspace <path>       Workspace root (repeatable). Default: cwd.
  --writable <path>        Writable directory root (repeatable). Ordinary
                           mutations inside these dirs can be auto-allowed.
  --home <path>            HOME for ~/ expansion (default: $HOME).
  --json                   Emit JSON output.
  --log-level <level>      Diagnostic log level: debug|info|warn|error|off
                           (default: off). Written to stderr.
  --audit <file>           Append a JSONL audit record per evaluated command.
                           Use "-" for stderr. (eval/explain only)

Exit codes:
  0  allow      10 ask     20 deny     30 parse error    40 policy error
`)
}

type commonFlags struct {
	policyPath string
	cwd        string
	workspace  multiFlag
	writable   multiFlag
	home       string
	jsonOut    bool
	logLevel   string
	auditPath  string
}

func setupCommon(fs *flag.FlagSet) *commonFlags {
	cf := &commonFlags{}
	fs.StringVar(&cf.policyPath, "policy", "", "policy YAML file")
	fs.StringVar(&cf.cwd, "cwd", "", "working directory")
	fs.Var(&cf.workspace, "workspace", "workspace root (repeatable)")
	fs.Var(&cf.writable, "writable", "writable directory root (repeatable)")
	fs.StringVar(&cf.home, "home", "", "home directory")
	fs.BoolVar(&cf.jsonOut, "json", false, "emit JSON")
	fs.StringVar(&cf.logLevel, "log-level", "off", "diagnostic log level: debug|info|warn|error|off")
	fs.StringVar(&cf.auditPath, "audit", "", "append JSONL audit records to this file (- for stderr)")
	return cf
}

func (cf *commonFlags) resolver() *paths.Resolver {
	cwd := cf.cwd
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	home := cf.home
	if home == "" {
		home = os.Getenv("HOME")
	}
	roots := append([]string(nil), cf.workspace...)
	if len(roots) == 0 {
		roots = []string{cwd}
	}
	return &paths.Resolver{Cwd: cwd, WorkspaceRoots: roots, Home: home, WritableRoots: append([]string(nil), cf.writable...)}
}

func (cf *commonFlags) loadPolicy() (*policy.Policy, error) {
	path := cf.policyPath
	if path == "" {
		// Try sibling default policy alongside the binary, or repo default.
		candidates := []string{
			"policies/default.yaml",
		}
		if exe, err := os.Executable(); err == nil {
			candidates = append(candidates, filepath.Join(filepath.Dir(exe), "policies/default.yaml"))
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				path = c
				break
			}
		}
		if path == "" {
			return nil, fmt.Errorf("no policy file found; pass --policy")
		}
	}
	return policy.LoadFromFile(path)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// readCommand pulls the command from positional args or stdin if none.
func readCommand(args []string) (string, error) {
	if len(args) > 0 {
		return strings.Join(args, " "), nil
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\n"), nil
}

// --- subcommands ---------------------------------------------------------

func cmdParse(args []string) int {
	fs := flag.NewFlagSet("parse", flag.ContinueOnError)
	jsonOut := fs.Bool("json", true, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cmd, err := readCommand(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	pr, err := parser.Parse(cmd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse error:", err)
		emitJSON(os.Stdout, pr, *jsonOut)
		return 30
	}
	emitJSON(os.Stdout, pr, *jsonOut)
	return 0
}

func cmdAnalyze(args []string) int {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	cf := setupCommon(fs)
	cf.jsonOut = true
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cmd, err := readCommand(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	pr, err := analyze.AnalyzeText(cmd, cf.resolver())
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse error:", err)
		return 30
	}
	emitJSON(os.Stdout, pr, true)
	return 0
}

func cmdEval(args []string, explain bool) int {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	cf := setupCommon(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cmd, err := readCommand(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	pol, err := cf.loadPolicy()
	if err != nil {
		fmt.Fprintln(os.Stderr, "policy error:", err)
		return 40
	}
	rsv := cf.resolver()
	// Writable dirs declared in the policy supplement those passed on the
	// command line, so an operator can ship the allowlist with the policy.
	rsv.WritableRoots = append(rsv.WritableRoots, pol.WritableDirs...)
	pr, err := analyze.AnalyzeText(cmd, rsv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse error:", err)
		emitDecision(&policy.Result{
			Decision:          "deny",
			EffectiveDecision: policy.EffectDeny,
			Reason:            "parse error: " + err.Error(),
		}, cf.jsonOut, explain, nil)
		return 30
	}
	eng := policy.New(pol).WithLogger(audit.NewLogger(os.Stderr, cf.logLevel))
	res, err := eng.Evaluate(pr.Command)
	if err != nil {
		fmt.Fprintln(os.Stderr, "policy error:", err)
		return 40
	}
	if aw, closeFn, err := cf.auditWriter(); err != nil {
		fmt.Fprintln(os.Stderr, "audit error:", err)
	} else if aw != nil {
		_ = aw.Write(auditRecordFor(cmd, rsv, res))
		if closeFn != nil {
			closeFn()
		}
	}
	emitDecision(res, cf.jsonOut, explain, pr)
	return exitCodeFor(res.EffectiveDecision)
}

// cmdClaudeHook acts as a Claude Code PreToolUse hook. It reads the hook
// payload from stdin, evaluates the Bash command against the policy, and
// writes a permission decision to stdout. Non-Bash tool calls and empty
// commands produce no output so Claude Code keeps its normal flow.
//
// The hook always exits 0 when it emits a JSON verdict: Claude Code reads
// the decision from stdout regardless of exit code, and a non-zero exit
// would instead be interpreted as a hook execution failure.
func cmdClaudeHook(args []string) int {
	fs := flag.NewFlagSet("claude-hook", flag.ContinueOnError)
	cf := setupCommon(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	in, err := claudehook.ParseInput(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "claude-hook: invalid input:", err)
		return 2
	}
	command, ok := in.BashCommand()
	if !ok {
		// Not a Bash command (or empty): do not interfere.
		return 0
	}
	// Prefer the cwd Claude Code reports unless the operator overrode it.
	if cf.cwd == "" {
		cf.cwd = in.Cwd
	}

	// Fail safe: any setup/parse/policy error asks the user rather than
	// silently allowing a command we could not fully evaluate.
	pol, err := cf.loadPolicy()
	if err != nil {
		return emitHookDecision(claudehook.Decision{
			Effective: claudehook.DecisionAsk,
			Reason:    "policy load error: " + err.Error(),
		})
	}
	rsv := cf.resolver()
	rsv.WritableRoots = append(rsv.WritableRoots, pol.WritableDirs...)
	pr, err := analyze.AnalyzeText(command, rsv)
	if err != nil {
		return emitHookDecision(claudehook.Decision{
			Effective: claudehook.DecisionAsk,
			Reason:    "parse error: " + err.Error(),
		})
	}
	eng := policy.New(pol).WithLogger(audit.NewLogger(os.Stderr, cf.logLevel))
	res, err := eng.Evaluate(pr.Command)
	if err != nil {
		return emitHookDecision(claudehook.Decision{
			Effective: claudehook.DecisionAsk,
			Reason:    "policy error: " + err.Error(),
		})
	}

	if aw, closeFn, err := cf.auditWriter(); err != nil {
		fmt.Fprintln(os.Stderr, "audit error:", err)
	} else if aw != nil {
		rec := auditRecordFor(command, rsv, res)
		rec.Session = in.SessionID
		_ = aw.Write(rec)
		if closeFn != nil {
			closeFn()
		}
	}

	return emitHookDecision(claudehook.Decision{
		Effective: string(res.EffectiveDecision),
		Reason:    res.Reason,
		Rule:      res.Decision,
		RiskScore: res.RiskScore,
		Tags:      res.Tags,
	})
}

// emitHookDecision writes a Claude Code permission verdict to stdout and
// returns the process exit code (always 0 for a delivered verdict).
func emitHookDecision(d claudehook.Decision) int {
	if err := claudehook.WriteOutput(os.Stdout, claudehook.BuildOutput(d)); err != nil {
		fmt.Fprintln(os.Stderr, "claude-hook: write output:", err)
		return 1
	}
	return 0
}

// auditWriter opens the audit sink selected by --audit. It returns a nil
// writer when auditing is disabled. The returned close function (if any)
// must be called to flush a file sink.
func (cf *commonFlags) auditWriter() (*audit.Writer, func(), error) {
	switch cf.auditPath {
	case "":
		return nil, nil, nil
	case "-":
		return audit.NewWriter(os.Stderr), nil, nil
	default:
		f, err := os.OpenFile(cf.auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, nil, err
		}
		return audit.NewWriter(f), func() { _ = f.Close() }, nil
	}
}

// auditRecordFor projects a policy.Result into an audit.Record.
func auditRecordFor(cmd string, rsv *paths.Resolver, res *policy.Result) audit.Record {
	rec := audit.Record{
		Command:           cmd,
		Cwd:               rsv.Cwd,
		Decision:          res.Decision,
		EffectiveDecision: string(res.EffectiveDecision),
		Reason:            res.Reason,
		RiskScore:         res.RiskScore,
		Tags:              res.Tags,
		AuditNotes:        res.AuditNotes,
	}
	if len(rsv.WorkspaceRoots) > 0 {
		rec.Workspace = rsv.WorkspaceRoots[0]
	}
	for _, mr := range res.MatchedRules {
		rec.MatchedRules = append(rec.MatchedRules, mr.RuleID)
	}
	return rec
}

func exitCodeFor(e policy.EffectiveAction) int {
	switch e {
	case policy.EffectAllow:
		return 0
	case policy.EffectAsk:
		return 10
	case policy.EffectDeny:
		return 20
	}
	return 40
}

func emitJSON(w io.Writer, v any, pretty bool) {
	enc := json.NewEncoder(w)
	if pretty {
		enc.SetIndent("", "  ")
	}
	_ = enc.Encode(v)
}

func emitDecision(res *policy.Result, jsonOut, explain bool, pr *parser.ParseResult) {
	if jsonOut {
		out := map[string]any{
			"decision":          res.Decision,
			"effectiveDecision": res.EffectiveDecision,
			"reason":            res.Reason,
			"riskScore":         res.RiskScore,
			"tags":              res.Tags,
			"auditNotes":        res.AuditNotes,
			"matchedRules":      res.MatchedRules,
			"operations":        res.Operations,
		}
		if explain {
			out["perLeaf"] = res.PerLeaf
			if pr != nil {
				out["commandTree"] = pr.Command
			}
		}
		emitJSON(os.Stdout, out, true)
		return
	}
	fmt.Printf("Decision: %s (%s)\n", res.Decision, res.EffectiveDecision)
	if res.Reason != "" {
		fmt.Printf("Reason:   %s\n", res.Reason)
	}
	fmt.Printf("Risk:     %d\n", res.RiskScore)
	if len(res.Tags) > 0 {
		fmt.Printf("Tags:     %s\n", strings.Join(res.Tags, ", "))
	}
	if len(res.AuditNotes) > 0 {
		fmt.Println("Audit:")
		for _, n := range res.AuditNotes {
			fmt.Printf("  - %s\n", n)
		}
	}
	if explain {
		fmt.Println("Trace:")
		for _, mr := range res.MatchedRules {
			marker := "→"
			if mr.Terminal {
				marker = "■"
			}
			fmt.Printf("  %s [%s] %s", marker, mr.Mode, mr.RuleID)
			if mr.Action != "" {
				fmt.Printf("  action=%s", mr.Action)
			}
			if mr.Reason != "" {
				fmt.Printf("  (%s)", mr.Reason)
			}
			fmt.Println()
		}
	}
}
