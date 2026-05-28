// Package ir defines the intermediate representation produced from a shell AST.
//
// The IR is the contract between the parser layer (mvdan.cc/sh/v3/syntax)
// and the policy / rule-chain engine. Policy decisions are made entirely
// against the IR — never directly against the raw AST nodes.
package ir

// Kind enumerates the node kinds supported by the IR.
type Kind string

const (
	KindSimple              Kind = "simple"
	KindPipeline            Kind = "pipeline"
	KindAnd                 Kind = "and"
	KindOr                  Kind = "or"
	KindSequence            Kind = "sequence"
	KindBackground          Kind = "background"
	KindSubshell            Kind = "subshell"
	KindCommandSubstitution Kind = "command_substitution"
	KindProcessSubstitution Kind = "process_substitution"
	KindFunction            Kind = "function"
	KindControlFlow         Kind = "control_flow"
)

// Confidence describes how reliably a string value was statically resolved.
type Confidence string

const (
	ConfStatic          Confidence = "static"
	ConfPartiallyStatic Confidence = "partially_static"
	ConfDynamic         Confidence = "dynamic"
)

// ArgValue is a parsed shell word together with metadata about how
// statically determinable its value is.
type ArgValue struct {
	Raw        string     `json:"raw"`
	Value      string     `json:"value,omitempty"`
	Confidence Confidence `json:"confidence"`
}

// RedirectOp models the kind of redirection in shell.
type RedirectOp string

const (
	RedirIn        RedirectOp = "<"
	RedirOut       RedirectOp = ">"
	RedirAppend    RedirectOp = ">>"
	RedirHeredoc   RedirectOp = "<<"
	RedirDupOut    RedirectOp = ">&"
	RedirDupIn     RedirectOp = "<&"
	RedirReadWrite RedirectOp = "<>"
	RedirClobber   RedirectOp = ">|"
	RedirOther     RedirectOp = "?"
)

// Redirect describes a single I/O redirection on a simple command.
type Redirect struct {
	Op     RedirectOp `json:"op"`
	FD     string     `json:"fd,omitempty"`
	Target ArgValue   `json:"target"`
}

// Assignment models a leading assignment word like FOO=bar before a command.
type Assignment struct {
	Name  string   `json:"name"`
	Value ArgValue `json:"value"`
}

// SimpleCommand is a single command invocation.
type SimpleCommand struct {
	Program     ArgValue     `json:"program"`
	Argv        []ArgValue   `json:"argv"`
	Assignments []Assignment `json:"assignments,omitempty"`

	// Filled by later phases.
	NormalizedProgram string             `json:"normalizedProgram,omitempty"`
	Wrapper           *WrapperInfo       `json:"wrapper,omitempty"`
	Operations        []ResourceOp       `json:"operations,omitempty"`
	Subcommand        []string           `json:"subcommand,omitempty"`
	Flags             map[string]any     `json:"flags,omitempty"`
	HasDynamicArgs    bool               `json:"hasDynamicArgs,omitempty"`
}

// Context is the contextual / propagated information attached to every node.
type Context struct {
	Depth                  int    `json:"depth"`
	InPipeline             bool   `json:"inPipeline,omitempty"`
	InSubshell             bool   `json:"inSubshell,omitempty"`
	InCommandSubstitution  bool   `json:"inCommandSubstitution,omitempty"`
	InProcessSubstitution  bool   `json:"inProcessSubstitution,omitempty"`
	InRemoteCommand        bool   `json:"inRemoteCommand,omitempty"`
	RemoteHost             string `json:"remoteHost,omitempty"`
	InContainerCommand     bool   `json:"inContainerCommand,omitempty"`
	ContainerName          string `json:"containerName,omitempty"`
	ContainerImage         string `json:"containerImage,omitempty"`
	PrivilegeEscalated     bool   `json:"privilegeEscalated,omitempty"`
	Background             bool   `json:"background,omitempty"`
}

// WrapperInfo records that a simple command is a known wrapper that
// nests an inner command (e.g. bash -c, ssh, docker exec).
type WrapperInfo struct {
	Type           string            `json:"type"`
	Outer          string            `json:"outer"`
	InnerText      string            `json:"innerText,omitempty"`
	InnerCommand   *Command          `json:"innerCommand,omitempty"`
	Host           string            `json:"host,omitempty"`
	User           string            `json:"user,omitempty"`
	Container      string            `json:"container,omitempty"`
	Image          string            `json:"image,omitempty"`
	Namespace      string            `json:"namespace,omitempty"`
	Privilege      bool              `json:"privilege,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
}

// SourceSpan locates an IR node in the original source text.
type SourceSpan struct {
	Text      string `json:"text,omitempty"`
	StartLine uint   `json:"startLine,omitempty"`
	StartCol  uint   `json:"startCol,omitempty"`
	EndLine   uint   `json:"endLine,omitempty"`
	EndCol    uint   `json:"endCol,omitempty"`
}

// Command is the IR node type.
type Command struct {
	ID        string         `json:"id"`
	Kind      Kind           `json:"kind"`
	Source    SourceSpan     `json:"source,omitempty"`
	Simple    *SimpleCommand `json:"simple,omitempty"`
	Children  []*Command     `json:"children,omitempty"`
	Redirects []Redirect     `json:"redirects,omitempty"`
	Context   Context        `json:"context"`
	RiskHints []string       `json:"riskHints,omitempty"`
}

// Walk visits all commands depth-first, including nested wrapper inner commands.
func Walk(c *Command, fn func(*Command)) {
	if c == nil {
		return
	}
	fn(c)
	for _, ch := range c.Children {
		Walk(ch, fn)
	}
	if c.Simple != nil && c.Simple.Wrapper != nil && c.Simple.Wrapper.InnerCommand != nil {
		Walk(c.Simple.Wrapper.InnerCommand, fn)
	}
}

// Leaves returns every simple-command leaf in evaluation order. Includes
// wrapper inner commands' leaves recursively.
func Leaves(c *Command) []*Command {
	var out []*Command
	Walk(c, func(n *Command) {
		if n.Kind == KindSimple && n.Simple != nil {
			out = append(out, n)
		}
	})
	return out
}
