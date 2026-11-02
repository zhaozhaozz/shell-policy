// Package docs embeds the user documentation so programs that use the
// engine (for example a web UI) can show the rule syntax next to the editor.
package docs

import _ "embed"

// AuthoringRules is docs/AUTHORING_RULES.md: the usage and rule-writing guide.
//
//go:embed AUTHORING_RULES.md
var AuthoringRules []byte
