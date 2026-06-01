package claudehook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseInputAndBashCommand(t *testing.T) {
	payload := `{
		"session_id": "s-1",
		"cwd": "/work",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {"command": "  rm -rf build  ", "description": "clean"}
	}`
	in, err := ParseInput(strings.NewReader(payload))
	if err != nil {
		t.Fatalf("ParseInput error: %v", err)
	}
	if in.SessionID != "s-1" || in.Cwd != "/work" {
		t.Fatalf("unexpected header fields: %+v", in)
	}
	cmd, ok := in.BashCommand()
	if !ok {
		t.Fatal("expected Bash command to be detected")
	}
	// The raw (untrimmed) command is returned for faithful evaluation.
	if cmd != "  rm -rf build  " {
		t.Fatalf("unexpected command: %q", cmd)
	}
}

func TestBashCommandNonBashTool(t *testing.T) {
	in := &HookInput{ToolName: "Read", ToolInput: ToolInput{Command: "anything"}}
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

func TestBuildOutputMapsDecisions(t *testing.T) {
	cases := []struct {
		effective string
		want      string
	}{
		{DecisionAllow, DecisionAllow},
		{DecisionAsk, DecisionAsk},
		{DecisionDeny, DecisionDeny},
		{"weird", DecisionAsk}, // unknown verdict fails safe to ask
		{"", DecisionAsk},
	}
	for _, tc := range cases {
		out := BuildOutput(Decision{Effective: tc.effective})
		if out.HookSpecificOutput.PermissionDecision != tc.want {
			t.Fatalf("effective %q -> %q, want %q", tc.effective,
				out.HookSpecificOutput.PermissionDecision, tc.want)
		}
		if out.HookSpecificOutput.HookEventName != "PreToolUse" {
			t.Fatalf("hookEventName = %q", out.HookSpecificOutput.HookEventName)
		}
	}
}

func TestFormatReasonIncludesTrace(t *testing.T) {
	out := BuildOutput(Decision{
		Effective: DecisionDeny,
		Reason:    "Secret-like file may be sent over network",
		Rule:      "deny-secret-exfiltration",
		RiskScore: 100,
		Tags:      []string{"secret_candidate", "network_write"},
	})
	r := out.HookSpecificOutput.PermissionDecisionReason
	for _, want := range []string{
		"[shell-policy]", "deny", "rule: deny-secret-exfiltration",
		"risk: 100", "secret_candidate", "Secret-like file may be sent over network",
	} {
		if !strings.Contains(r, want) {
			t.Fatalf("reason %q missing %q", r, want)
		}
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
	out := BuildOutput(Decision{Effective: DecisionAllow, Reason: "ok"})
	if err := WriteOutput(&buf, out); err != nil {
		t.Fatalf("WriteOutput error: %v", err)
	}
	var got HookOutput
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.HookSpecificOutput.PermissionDecision != DecisionAllow {
		t.Fatalf("round-trip decision = %q", got.HookSpecificOutput.PermissionDecision)
	}
}
