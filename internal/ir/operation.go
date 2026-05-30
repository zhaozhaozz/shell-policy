package ir

// OpType is the type of resource operation a command performs.
type OpType string

const (
	OpFileRead         OpType = "file_read"
	OpFileList         OpType = "file_list"
	OpFileReadMetadata OpType = "file_read_metadata"
	OpFileWrite        OpType = "file_write"
	OpFileAppend       OpType = "file_append"
	OpFileDelete       OpType = "file_delete"
	OpFileMove         OpType = "file_move"
	OpFileCopy         OpType = "file_copy"
	OpFileChmod        OpType = "file_chmod"
	OpFileChown        OpType = "file_chown"
	OpProcessExec      OpType = "process_exec"
	OpNetworkRead      OpType = "network_read"
	OpNetworkWrite     OpType = "network_write"
	OpGitRead          OpType = "git_read"
	OpGitWrite         OpType = "git_write"
	OpContainerRead    OpType = "container_read"
	OpContainerWrite   OpType = "container_write"
	OpRemoteExec       OpType = "remote_exec"
	OpPackageInstall   OpType = "package_install"
	OpUnknown          OpType = "unknown"
)

// PathScope classifies a path against the workspace / system context.
type PathScope string

const (
	ScopeInsideWorkspace  PathScope = "inside_workspace"
	ScopeOutsideWorkspace PathScope = "outside_workspace"
	ScopeHome             PathScope = "home"
	ScopeSystem           PathScope = "system"
	ScopeTmp              PathScope = "tmp"
	ScopeSecretCandidate  PathScope = "secret_candidate"
	ScopeHostMount        PathScope = "host_mount"
	ScopeContainerPath    PathScope = "container_path"
	ScopeStdin            PathScope = "stdin"
	ScopeStdout           PathScope = "stdout"
	ScopeRemote           PathScope = "remote"
	ScopeUnknown          PathScope = "unknown"
)

// PathKind classifies how the raw token expresses a path.
type PathKind string

const (
	PathWorkspaceRelative PathKind = "workspace_relative"
	PathAbsolute          PathKind = "absolute"
	PathHomeRelative      PathKind = "home_relative"
	PathDynamic           PathKind = "dynamic"
	PathGlob              PathKind = "glob"
	PathStdinDash         PathKind = "stdin_dash"
	PathStdoutDash        PathKind = "stdout_dash"
	PathRemote            PathKind = "remote"
	PathContainer         PathKind = "container_path"
	PathHostMount         PathKind = "host_mount"
)

// NormalizedPath is the canonical, classified form of a path argument.
type NormalizedPath struct {
	Raw             string    `json:"raw"`
	Normalized      string    `json:"normalized,omitempty"`
	Absolute        string    `json:"absolute,omitempty"`
	Kind            PathKind  `json:"kind"`
	Scope           PathScope `json:"scope"`
	SecretCandidate bool      `json:"secretCandidate,omitempty"`
	// Writable is true when the path falls inside one of the resolver's
	// configured writable roots (an operator-managed allowlist).
	Writable   bool       `json:"writable,omitempty"`
	Confidence Confidence `json:"confidence"`
}

// ResourceOp is a single resource operation produced by a command spec.
type ResourceOp struct {
	Type       OpType           `json:"type"`
	Paths      []NormalizedPath `json:"paths,omitempty"`
	Target     string           `json:"target,omitempty"`
	Subcommand []string         `json:"subcommand,omitempty"`
	Flags      map[string]any   `json:"flags,omitempty"`
	Confidence Confidence       `json:"confidence"`
	Dynamic    bool             `json:"dynamic,omitempty"`
	Context    Context          `json:"context"`
}
