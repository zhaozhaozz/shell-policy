package audit

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestWriterEmitsOneJSONLinePerRecord(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	if err := w.Write(Record{Command: "rm -rf /", Decision: "deny_destructive", EffectiveDecision: "deny", RiskScore: 90}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Write(Record{Command: "ls", Decision: "allow", EffectiveDecision: "allow"}); err != nil {
		t.Fatalf("write: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 JSONL lines, got %d: %q", len(lines), buf.String())
	}

	var first Record
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("unmarshal line 0: %v", err)
	}
	if first.Command != "rm -rf /" || first.EffectiveDecision != "deny" {
		t.Fatalf("unexpected record: %#v", first)
	}
	if first.Time.IsZero() {
		t.Fatal("timestamp should be auto-stamped")
	}
}

func TestWriterStampPreservesProvidedTime(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	ts := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := w.Write(Record{Command: "ls", Time: ts}); err != nil {
		t.Fatalf("write: %v", err)
	}
	var rec Record
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !rec.Time.Equal(ts) {
		t.Fatalf("time = %v, want %v", rec.Time, ts)
	}
}

func TestNilWriterIsNoOp(t *testing.T) {
	var w *Writer
	if err := w.Write(Record{Command: "ls"}); err != nil {
		t.Fatalf("nil writer should be a no-op, got %v", err)
	}
}

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in      string
		want    slog.Level
		enabled bool
	}{
		{"debug", slog.LevelDebug, true},
		{"INFO", slog.LevelInfo, true},
		{"warning", slog.LevelWarn, true},
		{"error", slog.LevelError, true},
		{"", slog.LevelWarn, false},
		{"off", slog.LevelWarn, false},
		{"bogus", slog.LevelWarn, true},
	}
	for _, tc := range cases {
		got, enabled := ParseLevel(tc.in)
		if got != tc.want || enabled != tc.enabled {
			t.Fatalf("ParseLevel(%q) = %v/%v, want %v/%v", tc.in, got, enabled, tc.want, tc.enabled)
		}
	}
}

func TestNewLoggerRespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger(&buf, "warn")
	log.Debug("hidden")
	log.Warn("shown")
	out := buf.String()
	if strings.Contains(out, "hidden") {
		t.Fatalf("debug record should be filtered at warn level: %q", out)
	}
	if !strings.Contains(out, "shown") {
		t.Fatalf("warn record should be emitted: %q", out)
	}

	// An "off" level discards everything.
	buf.Reset()
	NewLogger(&buf, "off").Error("nope")
	if buf.Len() != 0 {
		t.Fatalf("off level should discard output, got %q", buf.String())
	}
}
