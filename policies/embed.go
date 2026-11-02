// Package policies embeds the built-in policy files so programs do not need
// them on disk.
package policies

import _ "embed"

// DefaultYAML is policies/default.yaml.
//
//go:embed default.yaml
var DefaultYAML []byte
