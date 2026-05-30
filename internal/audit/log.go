package audit

import (
	"io"
	"log/slog"
	"strings"
)

// ParseLevel maps a human-friendly level name to an slog.Level. Unknown
// names default to warn. The bool result is false for the special
// "silent" values ("", "off", "none", "silent"), signaling that the
// caller should discard diagnostic output entirely.
func ParseLevel(level string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "off", "none", "silent":
		return slog.LevelWarn, false
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	default:
		return slog.LevelWarn, true
	}
}

// NewLogger builds a leveled text logger writing to w. The level is one of
// debug/info/warn/error (case-insensitive). The special values "", "off",
// "none" and "silent" produce a logger that discards everything, so the
// engine can always be handed a non-nil *slog.Logger.
func NewLogger(w io.Writer, level string) *slog.Logger {
	lv, enabled := ParseLevel(level)
	if !enabled || w == nil {
		return Discard()
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: lv}))
}

// Discard returns a logger that drops all records. Use it as a safe
// default so logging calls never need nil checks.
func Discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
