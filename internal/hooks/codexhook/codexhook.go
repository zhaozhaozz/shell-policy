// Package codexhook adapts shell-policy decisions to the Codex CLI
// PermissionRequest hook protocol.
//
// Codex runs PermissionRequest hooks after it has decided a tool call needs
// approval, but before showing the normal approval UI. A hook may return an
// allow/deny verdict, or no decision to let Codex continue its default flow.
package codexhook

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ToolName is the normalized Codex hook tool name for shell commands.
const ToolName = "Bash"

// Permission request decisions understood by Codex PermissionRequest hooks.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
	DecisionAsk   = "ask"
)

// ToolInput is the subset of the Codex hook payload this adapter evaluates.
type ToolInput struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

// HookInput is the JSON object Codex writes to the hook's stdin.
type HookInput struct {
	SessionID      string    `json:"session_id"`
	TurnID         string    `json:"turn_id"`
	TranscriptPath string    `json:"transcript_path"`
	Cwd            string    `json:"cwd"`
	HookEventName  string    `json:"hook_event_name"`
	Model          string    `json:"model"`
	PermissionMode string    `json:"permission_mode"`
	ToolName       string    `json:"tool_name"`
	ToolInput      ToolInput `json:"tool_input"`
}

// HookOutput is the JSON object the hook writes to stdout. A nil output writes
// nothing, which leaves Codex's normal approval flow in charge.
type HookOutput struct {
	HookSpecificOutput *HookSpecificOutput `json:"hookSpecificOutput,omitempty"`
	SystemMessage      string              `json:"systemMessage,omitempty"`
}

// HookSpecificOutput carries the permission verdict back to Codex.
type HookSpecificOutput struct {
	HookEventName string          `json:"hookEventName"`
	Decision      *DecisionOutput `json:"decision,omitempty"`
}

// DecisionOutput is the Codex PermissionRequest decision shape.
type DecisionOutput struct {
	Behavior string `json:"behavior"`
	Message  string `json:"message,omitempty"`
}

// Decision is the engine-agnostic verdict the adapter maps into the Codex
// hook protocol.
type Decision struct {
	// Effective is the final classification: "allow", "ask", or "deny".
	Effective string
	// Reason is a human-readable explanation shown to the user/agent.
	Reason string
	// Rule is the id/name of the deciding rule, included for traceability.
	Rule string
	// RiskScore is the accumulated risk, surfaced in denial messages.
	RiskScore int
	// Tags are enrichment tags, surfaced in denial messages.
	Tags []string
}

// ParseInput decodes the PermissionRequest payload from r.
func ParseInput(r io.Reader) (*HookInput, error) {
	var in HookInput
	dec := json.NewDecoder(r)
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("decode hook input: %w", err)
	}
	return &in, nil
}

// BashCommand returns the shell command to audit and true when the request is a
// Bash permission request carrying a non-empty command. Other tools should not
// be handled by this shell-policy adapter.
func (h *HookInput) BashCommand() (string, bool) {
	if h == nil || h.ToolName != ToolName {
		return "", false
	}
	cmd := strings.TrimSpace(h.ToolInput.Command)
	if cmd == "" {
		return "", false
	}
	return h.ToolInput.Command, true
}

// BuildOutput converts a Decision into a Codex PermissionRequest output. An
// "ask" decision deliberately returns nil: PermissionRequest has no ask
// behavior, and no hook decision makes Codex continue the normal approval flow.
func BuildOutput(d Decision) *HookOutput {
	switch d.Effective {
	case DecisionAllow:
		return &HookOutput{
			HookSpecificOutput: &HookSpecificOutput{
				HookEventName: "PermissionRequest",
				Decision:      &DecisionOutput{Behavior: DecisionAllow},
			},
		}
	case DecisionDeny:
		return &HookOutput{
			HookSpecificOutput: &HookSpecificOutput{
				HookEventName: "PermissionRequest",
				Decision: &DecisionOutput{
					Behavior: DecisionDeny,
					Message:  formatReason(d),
				},
			},
		}
	default:
		return nil
	}
}

// BuildNoDecision returns a warning-only hook output. Codex will not approve or
// deny from this output, but the hook row can explain why it declined.
func BuildNoDecision(message string) *HookOutput {
	message = strings.TrimSpace(message)
	if message == "" {
		return nil
	}
	return &HookOutput{SystemMessage: "[shell-policy] " + message}
}

// formatReason renders a compact, single-line explanation.
func formatReason(d Decision) string {
	var meta []string
	if d.Rule != "" {
		meta = append(meta, "rule: "+d.Rule)
	}
	meta = append(meta, fmt.Sprintf("risk: %d", d.RiskScore))
	if len(d.Tags) > 0 {
		meta = append(meta, "tags: "+strings.Join(d.Tags, ","))
	}

	var b strings.Builder
	b.WriteString("[shell-policy] ")
	b.WriteString(DecisionDeny)
	if len(meta) > 0 {
		b.WriteString(" (")
		b.WriteString(strings.Join(meta, ", "))
		b.WriteString(")")
	}
	if reason := strings.TrimSpace(d.Reason); reason != "" {
		b.WriteString(": ")
		b.WriteString(reason)
	}
	return b.String()
}

// WriteOutput serializes out as a single JSON line to w. A nil out writes
// nothing, which signals Codex to use its normal approval flow.
func WriteOutput(w io.Writer, out *HookOutput) error {
	if out == nil {
		return nil
	}
	enc := json.NewEncoder(w)
	return enc.Encode(out)
}
