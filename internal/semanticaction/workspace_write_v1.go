package semanticaction

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/szey/Aegis_Router/internal/canonicalaction"
	"github.com/szey/Aegis_Router/internal/models"
)

const (
	WorkspaceWriteV1ID              = "workspace.write/v1"
	DefaultWorkspaceMaxPathBytes    = 1024
	DefaultWorkspaceMaxContentBytes = 4 * 1024
)

const (
	RejectWorkspaceToolUnmapped     RejectionCode = "WORKSPACE_TOOL_UNMAPPED"
	RejectWorkspaceBindingConflict  RejectionCode = "WORKSPACE_BINDING_CONFLICT"
	RejectWorkspaceProfileMismatch  RejectionCode = "WORKSPACE_PROFILE_MISMATCH"
	RejectWorkspaceAudienceMismatch RejectionCode = "WORKSPACE_AUDIENCE_MISMATCH"
	RejectWorkspaceArgumentsInvalid RejectionCode = "WORKSPACE_ARGUMENTS_INVALID"
	RejectWorkspacePathInvalid      RejectionCode = "WORKSPACE_PATH_INVALID"
	RejectWorkspaceContentTooLarge  RejectionCode = "WORKSPACE_CONTENT_TOO_LARGE"
)

var windowsDrivePrefix = regexp.MustCompile(`^[A-Za-z]:`)

type WorkspaceWriteArguments struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type WorkspaceWriteV1 struct {
	binding         string
	config          models.WorkspaceWriteV1Config
	maxPathBytes    int
	maxContentBytes int
	upstream        *url.URL
}

func NewWorkspaceWriteV1(config models.WorkspaceWriteV1Config) (*WorkspaceWriteV1, error) {
	if config.ProfileID != WorkspaceWriteV1ID || config.MCPTool != "workspace.write" ||
		strings.TrimSpace(config.Capability) == "" || strings.TrimSpace(config.Resource) == "" ||
		strings.TrimSpace(config.Operation) == "" || strings.TrimSpace(config.Audience) == "" {
		return nil, fmt.Errorf("invalid %s binding configuration", WorkspaceWriteV1ID)
	}
	upstream, err := url.Parse(strings.TrimSpace(config.UpstreamURL))
	if err != nil || upstream.Scheme == "" || upstream.Host == "" || (upstream.Scheme != "http" && upstream.Scheme != "https") {
		return nil, fmt.Errorf("%s upstream_url must be an absolute HTTP(S) URL", WorkspaceWriteV1ID)
	}
	maxPathBytes := config.MaxPathBytes
	if maxPathBytes == 0 {
		maxPathBytes = DefaultWorkspaceMaxPathBytes
	}
	maxContentBytes := config.MaxContentBytes
	if maxContentBytes == 0 {
		maxContentBytes = DefaultWorkspaceMaxContentBytes
	}
	if maxPathBytes < 1 || maxPathBytes > canonicalaction.MaxArgumentsBytes {
		return nil, fmt.Errorf("%s max_path_bytes is outside the supported range", WorkspaceWriteV1ID)
	}
	if maxContentBytes < 1 || maxContentBytes > canonicalaction.MaxArgumentsBytes {
		return nil, fmt.Errorf("%s max_content_bytes is outside the supported range", WorkspaceWriteV1ID)
	}
	if upstream.User != nil || upstream.Fragment != "" || upstream.RawQuery != "" || upstream.ForceQuery {
		return nil, fmt.Errorf("%s upstream cannot contain credentials, query, or fragment", WorkspaceWriteV1ID)
	}
	config.UpstreamURL = upstream.String()
	config.MaxPathBytes, config.MaxContentBytes = maxPathBytes, maxContentBytes
	binding, err := executionBinding(config, upstream.String())
	if err != nil {
		return nil, err
	}
	return &WorkspaceWriteV1{config: config, maxPathBytes: maxPathBytes, maxContentBytes: maxContentBytes, upstream: upstream, binding: binding}, nil
}

func (p *WorkspaceWriteV1) Tool() string          { return p.config.MCPTool }
func (p *WorkspaceWriteV1) ProfileID() string     { return p.config.ProfileID }
func (p *WorkspaceWriteV1) Audience() string      { return p.config.Audience }
func (p *WorkspaceWriteV1) UpstreamURL() string   { return p.upstream.String() }
func (p *WorkspaceWriteV1) BindingDigest() string { return p.binding }

func (p *WorkspaceWriteV1) Resolve(input Input) (Resolved, error) {
	if p == nil || input.Tool != p.config.MCPTool {
		return Resolved{}, &Rejection{Code: RejectWorkspaceToolUnmapped, Detail: "MCP tool has no workspace.write/v1 mapping"}
	}
	if input.Capability == "" || input.Resource == "" || input.Operation == "" ||
		input.Capability != p.config.Capability || input.Resource != p.config.Resource || input.Operation != p.config.Operation {
		return Resolved{}, &Rejection{Code: RejectWorkspaceBindingConflict, Detail: "capability, resource, and operation must exactly match the server mapping"}
	}
	if input.ProfileID != "" && input.ProfileID != p.config.ProfileID {
		return Resolved{}, &Rejection{Code: RejectWorkspaceProfileMismatch, Detail: "client profile assertion conflicts with the server mapping"}
	}
	if input.Audience != "" && input.Audience != p.config.Audience {
		return Resolved{}, &Rejection{Code: RejectWorkspaceAudienceMismatch, Detail: "client audience assertion conflicts with the server mapping"}
	}
	arguments, err := p.parseArguments(input.Arguments)
	if err != nil {
		return Resolved{}, err
	}
	normalized, err := json.Marshal(arguments)
	if err != nil {
		return Resolved{}, &Rejection{Code: RejectWorkspaceArgumentsInvalid, Detail: "could not normalize workspace arguments"}
	}
	action := canonicalaction.Action{
		PrincipalID: input.PrincipalID, AgentID: input.AgentID, WorkloadID: input.WorkloadID,
		DelegatedAuthorityFingerprint: input.DelegatedAuthorityFingerprint,
		Tool:                          p.config.MCPTool, Capability: p.config.Capability, Resource: p.config.Resource,
		Operation: p.config.Operation, ProfileID: p.config.ProfileID, Audience: p.config.Audience,
		Arguments: normalized,
	}
	return Resolved{Action: action, NormalizedArguments: normalized, UpstreamURL: p.upstream.String(),
		PolicyFacts: PolicyFacts{SideEffect: "logical_workspace_write", Bytes: int64(len(arguments.Content))}}, nil
}

func (p *WorkspaceWriteV1) parseArguments(raw json.RawMessage) (WorkspaceWriteArguments, error) {
	if _, err := canonicalaction.CanonicalizeJSON(raw); err != nil {
		return WorkspaceWriteArguments{}, &Rejection{Code: RejectWorkspaceArgumentsInvalid, Detail: "arguments must be unambiguous JSON"}
	}
	var wire struct {
		Path    *string `json:"path"`
		Content *string `json:"content"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return WorkspaceWriteArguments{}, &Rejection{Code: RejectWorkspaceArgumentsInvalid, Detail: "only path and content with exact JSON string types are allowed"}
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return WorkspaceWriteArguments{}, &Rejection{Code: RejectWorkspaceArgumentsInvalid, Detail: "trailing JSON is not allowed"}
	}
	if wire.Path == nil || wire.Content == nil {
		return WorkspaceWriteArguments{}, &Rejection{Code: RejectWorkspaceArgumentsInvalid, Detail: "path and content are required"}
	}
	if err := p.validateLogicalPath(*wire.Path); err != nil {
		return WorkspaceWriteArguments{}, err
	}
	if !utf8.ValidString(*wire.Content) || len([]byte(*wire.Content)) > p.maxContentBytes {
		return WorkspaceWriteArguments{}, &Rejection{Code: RejectWorkspaceContentTooLarge, Detail: "content exceeds the server-owned UTF-8 byte limit"}
	}
	return WorkspaceWriteArguments{Path: *wire.Path, Content: *wire.Content}, nil
}

func (p *WorkspaceWriteV1) validateLogicalPath(path string) error {
	invalid := path == "" || !utf8.ValidString(path) || len([]byte(path)) > p.maxPathBytes ||
		strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") || strings.Contains(path, `\`) ||
		windowsDrivePrefix.MatchString(path) || strings.IndexFunc(path, unicode.IsControl) >= 0
	if invalid {
		return &Rejection{Code: RejectWorkspacePathInvalid, Detail: "path is not a valid workspace-relative logical path"}
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || segment == "." || segment == ".." || segment == "~" {
			return &Rejection{Code: RejectWorkspacePathInvalid, Detail: "path contains a forbidden logical segment"}
		}
	}
	return nil
}
