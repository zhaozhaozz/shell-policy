// Package claudehook adapts the shell-policy decision engine to the
// Claude Code PreToolUse hook protocol.
//
// It is deliberately decoupled from the policy/analyze packages: it only
// knows the Claude Code wire format and a small engine-agnostic Decision
// type. The CLI glue layer is responsible for running the policy engine
// and translating its Result into a Decision. This keeps the protocol
// adapter independently testable and prevents the core engine from
// growing Claude-specific concerns.
//
// Protocol reference: Claude Code invokes a PreToolUse hook with a JSON
// object on stdin and reads a JSON object on stdout. For permission
// control the hook emits a "hookSpecificOutput" carrying a
// "permissionDecision" of allow / deny / ask. Emitting no JSON (and
// exiting 0) lets Claude Code fall back to its normal permission flow.
package claudehook

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ToolName is the Claude Code tool whose commands this hook audits.
const ToolName = "Bash"

// Permission decision values understood by Claude Code's PreToolUse hook.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
	DecisionAsk   = "ask"
)

// ToolInput is the subset of a tool call payload this hook cares about.
// Claude Code's Bash tool puts the shell command in "command".
type ToolInput struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

// HookInput is the JSON object Claude Code writes to the hook's stdin.
// Fields not used by the adapter are kept so callers can read them (e.g.
// SessionID for audit correlation) without re-parsing.
type HookInput struct {
	SessionID      string    `json:"session_id"`
	TranscriptPath string    `json:"transcript_path"`
	Cwd            string    `json:"cwd"`
	HookEventName  string    `json:"hook_event_name"`
	ToolName       string    `json:"tool_name"`
	ToolInput      ToolInput `json:"tool_input"`
}

// HookSpecificOutput carries the permission verdict back to Claude Code.
type HookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// HookOutput is the JSON object the hook writes to stdout.
type HookOutput struct {
	HookSpecificOutput *HookSpecificOutput `json:"hookSpecificOutput,omitempty"`
	SuppressOutput     bool                `json:"suppressOutput,omitempty"`
}

// Decision is the engine-agnostic verdict the adapter maps into the hook
// protocol. The glue layer fills it from a policy.Result.
type Decision struct {
	// Effective is the final classification: "allow", "ask", or "deny".
	Effective string
	// Reason is a human-readable explanation shown to the user/agent.
	Reason string
	// Rule is the id/name of the deciding rule, included for traceability.
	Rule string
	// RiskScore is the accumulated risk, surfaced in the reason text.
	RiskScore int
	// Tags are enrichment tags, surfaced in the reason text.
	Tags []string
}

// ParseInput decodes the PreToolUse payload from r. It does not validate
// the event name so the same adapter can be reused for other tool events.
func ParseInput(r io.Reader) (*HookInput, error) {
	var in HookInput
	dec := json.NewDecoder(r)
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("decode hook input: %w", err)
	}
	return &in, nil
}

// BashCommand returns the shell command to audit and true when the tool
// call is a Bash invocation carrying a non-empty command. For any other
// tool the hook should not interfere and the bool is false.
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

// normalizeDecision maps an effective action to a Claude Code permission
// decision, defaulting to "ask" for anything unexpected so an unknown
// verdict never silently allows a command.
func normalizeDecision(effective string) string {
	switch effective {
	case DecisionAllow, DecisionDeny, DecisionAsk:
		return effective
	default:
		return DecisionAsk
	}
}

// BuildOutput converts a Decision into a HookOutput ready to be written
// to stdout. The reason string is enriched with the deciding rule, risk
// score, and tags so the user sees why a command was gated.
func BuildOutput(d Decision) *HookOutput {
	return &HookOutput{
		HookSpecificOutput: &HookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       normalizeDecision(d.Effective),
			PermissionDecisionReason: formatReason(d),
		},
	}
}

// formatReason renders a compact, single-line explanation, e.g.
// "[shell-policy] deny (rule: deny-secret-exfiltration, risk: 100, tags:
// secret_candidate,network_write): Secret-like file may be sent over
// network".
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
	b.WriteString(normalizeDecision(d.Effective))
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
// nothing, which signals Claude Code to use its normal permission flow.
func WriteOutput(w io.Writer, out *HookOutput) error {
	if out == nil {
		return nil
	}
	enc := json.NewEncoder(w)
	return enc.Encode(out)
}
