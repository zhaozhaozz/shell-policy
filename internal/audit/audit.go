// Package audit provides two complementary logging facilities for the
// shell-policy engine:
//
//  1. A structured audit trail (Record / Writer) that records one JSON
//     line per evaluated command, intended for security review and replay.
//  2. A leveled diagnostic logger (NewLogger) built on log/slog, intended
//     for debugging the parse/analyze/match pipeline.
//
// The two are kept separate on purpose: the audit trail is a stable,
// machine-readable record of decisions, while diagnostics are free-form
// developer output whose verbosity is controlled by a log level.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Record is a single decision audit entry, serialized as one JSON line.
// Fields mirror the policy.Result so a reviewer can reconstruct why a
// command was allowed, asked about, or denied.
type Record struct {
	Time              time.Time `json:"time"`
	Command           string    `json:"command"`
	Cwd               string    `json:"cwd,omitempty"`
	Workspace         string    `json:"workspace,omitempty"`
	Decision          string    `json:"decision"`
	EffectiveDecision string    `json:"effectiveDecision"`
	Reason            string    `json:"reason,omitempty"`
	RiskScore         int       `json:"riskScore"`
	Tags              []string  `json:"tags,omitempty"`
	MatchedRules      []string  `json:"matchedRules,omitempty"`
	AuditNotes        []string  `json:"auditNotes,omitempty"`
	Actor             string    `json:"actor,omitempty"`
	Session           string    `json:"session,omitempty"`
}

// Writer appends audit records as JSON Lines (one compact JSON object per
// line). It is safe for concurrent use. A nil Writer is a no-op, which
// lets callers keep the audit trail optional without nil checks at every
// call site.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

// NewWriter returns a Writer that appends records to w. Passing a nil w
// yields a Writer whose Write is a no-op.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

// Write serializes r as a single JSON line. When the record carries no
// timestamp the current time is stamped automatically.
func (w *Writer) Write(r Record) error {
	if w == nil || w.w == nil {
		return nil
	}
	if r.Time.IsZero() {
		r.Time = time.Now().UTC()
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()
	_, err = w.w.Write(b)
	return err
}
