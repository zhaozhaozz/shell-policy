package codexhook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseInputAndBashCommand(t *testing.T) {
	payload := `{
		"session_id": "s-1",
		"turn_id": "t-1",
		"cwd": "/work",
		"hook_event_name": "PermissionRequest",
		"tool_name": "Bash",
		"tool_input": {"command": "  rm -rf build  ", "description": "clean"}
	}`
	in, err := ParseInput(strings.NewReader(payload))
	if err != nil {
		t.Fatalf("ParseInput error: %v", err)
	}
	if in.SessionID != "s-1" || in.TurnID != "t-1" || in.Cwd != "/work" {
		t.Fatalf("unexpected header fields: %+v", in)
	}
	cmd, ok := in.BashCommand()
	if !ok {
		t.Fatal("expected Bash command to be detected")
	}
	if cmd != "  rm -rf build  " {
		t.Fatalf("unexpected command: %q", cmd)
	}
}

func TestBashCommandNonBashTool(t *testing.T) {
	in := &HookInput{ToolName: "apply_patch", ToolInput: ToolInput{Command: "anything"}}
	if _, ok := in.BashCommand(); ok {
		t.Fatal("non-Bash tool must not be audited")
	}
}

func TestBashCommandEmpty(t *testing.T) {
	in := &HookInput{ToolName: "Bash", ToolInput: ToolInput{Command: "   "}}
	if _, ok := in.BashCommand(); ok {
		t.Fatal("empty command must not be audited")
	}
}

func TestParseInputInvalid(t *testing.T) {
	if _, err := ParseInput(strings.NewReader("not json")); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestBuildOutputAllow(t *testing.T) {
	out := BuildOutput(Decision{Effective: DecisionAllow})
	if out == nil || out.HookSpecificOutput == nil || out.HookSpecificOutput.Decision == nil {
		t.Fatalf("expected allow output, got %+v", out)
	}
	if out.HookSpecificOutput.HookEventName != "PermissionRequest" {
		t.Fatalf("hookEventName = %q", out.HookSpecificOutput.HookEventName)
	}
	if got := out.HookSpecificOutput.Decision.Behavior; got != DecisionAllow {
		t.Fatalf("behavior = %q, want %q", got, DecisionAllow)
	}
}

func TestBuildOutputDenyIncludesTrace(t *testing.T) {
	out := BuildOutput(Decision{
		Effective: DecisionDeny,
		Reason:    "Secret-like file may be sent over network",
		Rule:      "deny-secret-exfiltration",
		RiskScore: 100,
		Tags:      []string{"secret_candidate", "network_write"},
	})
	if out == nil || out.HookSpecificOutput == nil || out.HookSpecificOutput.Decision == nil {
		t.Fatalf("expected deny output, got %+v", out)
	}
	decision := out.HookSpecificOutput.Decision
	if decision.Behavior != DecisionDeny {
		t.Fatalf("behavior = %q, want %q", decision.Behavior, DecisionDeny)
	}
	for _, want := range []string{
		"[shell-policy]", "deny", "rule: deny-secret-exfiltration",
		"risk: 100", "secret_candidate", "Secret-like file may be sent over network",
	} {
		if !strings.Contains(decision.Message, want) {
			t.Fatalf("message %q missing %q", decision.Message, want)
		}
	}
}

func TestBuildOutputAskWritesNoDecision(t *testing.T) {
	if out := BuildOutput(Decision{Effective: DecisionAsk}); out != nil {
		t.Fatalf("ask should produce no hook decision, got %+v", out)
	}
}

func TestBuildNoDecision(t *testing.T) {
	out := BuildNoDecision("parse error")
	if out == nil {
		t.Fatal("expected warning output")
	}
	if out.HookSpecificOutput != nil {
		t.Fatalf("warning-only output must not decide, got %+v", out.HookSpecificOutput)
	}
	if !strings.Contains(out.SystemMessage, "parse error") {
		t.Fatalf("systemMessage = %q", out.SystemMessage)
	}
}

func TestWriteOutputNilWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteOutput(&buf, nil); err != nil {
		t.Fatalf("WriteOutput error: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected no output, got %q", buf.String())
	}
}

func TestWriteOutputRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	out := BuildOutput(Decision{Effective: DecisionAllow})
	if err := WriteOutput(&buf, out); err != nil {
		t.Fatalf("WriteOutput error: %v", err)
	}
	var got HookOutput
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.HookSpecificOutput.Decision.Behavior != DecisionAllow {
		t.Fatalf("round-trip behavior = %q", got.HookSpecificOutput.Decision.Behavior)
	}
}
