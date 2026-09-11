package semanticaction_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/szey/Aegis_Router/internal/models"
	"github.com/szey/Aegis_Router/internal/semanticaction"
)

func TestWorkspaceWriteV1ValidatesAndNormalizesExactSemantics(t *testing.T) {
	profile := testWorkspaceProfile(t)
	first, err := profile.Resolve(validWorkspaceInput(`{"path":"reports/result.txt","content":"hello"}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := profile.Resolve(validWorkspaceInput(`{"content":"hello","path":"reports/result.txt"}`))
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, _ := first.Action.Digest()
	secondDigest, _ := second.Action.Digest()
	if firstDigest != secondDigest || string(first.NormalizedArguments) != `{"path":"reports/result.txt","content":"hello"}` {
		t.Fatalf("normalization mismatch: %s / %s / %s", firstDigest, secondDigest, first.NormalizedArguments)
	}
	if first.Action.ProfileID != semanticaction.WorkspaceWriteV1ID || first.Action.Audience != "mcp://test-workspace-upstream" {
		t.Fatalf("server binding missing: %#v", first.Action)
	}
}

func TestWorkspaceWriteV1RejectsInvalidLogicalPaths(t *testing.T) {
	profile := testWorkspaceProfile(t)
	paths := []string{
		"../secret.txt", "/reports/result.txt", "reports/../secret.txt", "reports/./result.txt",
		"reports//result.txt", `reports\result.txt`, `C:\temp\file.txt`, "C:/temp/file.txt", "~", ".", "..",
		"reports/result.txt/", "reports/\u0001result.txt", strings.Repeat("a", semanticaction.DefaultWorkspaceMaxPathBytes+1),
	}
	for _, path := range paths {
		t.Run(strings.ReplaceAll(path, "/", "_"), func(t *testing.T) {
			raw, _ := json.Marshal(map[string]string{"path": path, "content": "hello"})
			_, err := profile.Resolve(validWorkspaceInput(string(raw)))
			if err == nil || semanticaction.Code(err) != semanticaction.RejectWorkspacePathInvalid {
				t.Fatalf("path %q error=%v code=%s", path, err, semanticaction.Code(err))
			}
		})
	}
}

func TestWorkspaceWriteV1RejectsInvalidArgumentsAndOversizedContent(t *testing.T) {
	profile := testWorkspaceProfile(t)
	tests := []struct {
		name string
		raw  string
		code semanticaction.RejectionCode
	}{
		{"missing path", `{"content":"hello"}`, semanticaction.RejectWorkspaceArgumentsInvalid},
		{"missing content", `{"path":"reports/a.txt"}`, semanticaction.RejectWorkspaceArgumentsInvalid},
		{"path wrong type", `{"path":12,"content":"hello"}`, semanticaction.RejectWorkspaceArgumentsInvalid},
		{"content wrong type", `{"path":"reports/a.txt","content":12}`, semanticaction.RejectWorkspaceArgumentsInvalid},
		{"unknown field", `{"path":"reports/a.txt","content":"hello","mode":"0777"}`, semanticaction.RejectWorkspaceArgumentsInvalid},
		{"duplicate field", `{"path":"reports/a.txt","content":"hello","content":"goodbye"}`, semanticaction.RejectWorkspaceArgumentsInvalid},
		{"trailing JSON", `{"path":"reports/a.txt","content":"hello"}{}`, semanticaction.RejectWorkspaceArgumentsInvalid},
		{"oversized", `{"path":"reports/a.txt","content":"` + strings.Repeat("x", semanticaction.DefaultWorkspaceMaxContentBytes+1) + `"}`, semanticaction.RejectWorkspaceContentTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := profile.Resolve(validWorkspaceInput(test.raw))
			if err == nil || semanticaction.Code(err) != test.code {
				t.Fatalf("error=%v code=%s, want %s", err, semanticaction.Code(err), test.code)
			}
		})
	}
}

func TestWorkspaceWriteV1RejectsCallerBindingConflicts(t *testing.T) {
	profile := testWorkspaceProfile(t)
	tests := []struct {
		name   string
		mutate func(*semanticaction.Input)
		code   semanticaction.RejectionCode
	}{
		{"unknown tool", func(input *semanticaction.Input) { input.Tool = "workspace.delete" }, semanticaction.RejectWorkspaceToolUnmapped},
		{"capability", func(input *semanticaction.Input) { input.Capability = "workspace_admin" }, semanticaction.RejectWorkspaceBindingConflict},
		{"resource", func(input *semanticaction.Input) { input.Resource = "host-filesystem" }, semanticaction.RejectWorkspaceBindingConflict},
		{"operation", func(input *semanticaction.Input) { input.Operation = "delete" }, semanticaction.RejectWorkspaceBindingConflict},
		{"profile", func(input *semanticaction.Input) { input.ProfileID = "workspace.write/v2" }, semanticaction.RejectWorkspaceProfileMismatch},
		{"audience", func(input *semanticaction.Input) { input.Audience = "mcp://attacker" }, semanticaction.RejectWorkspaceAudienceMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validWorkspaceInput(`{"path":"reports/a.txt","content":"hello"}`)
			test.mutate(&input)
			_, err := profile.Resolve(input)
			if err == nil || semanticaction.Code(err) != test.code {
				t.Fatalf("error=%v code=%s, want %s", err, semanticaction.Code(err), test.code)
			}
		})
	}
}

func testWorkspaceProfile(t *testing.T) *semanticaction.WorkspaceWriteV1 {
	t.Helper()
	profile, err := semanticaction.NewWorkspaceWriteV1(models.WorkspaceWriteV1Config{
		ProfileID: semanticaction.WorkspaceWriteV1ID, MCPTool: "workspace.write", Capability: "workspace_write",
		Resource: "demo-workspace", Operation: "write", Audience: "mcp://test-workspace-upstream",
		UpstreamURL: "http://127.0.0.1:3002/mcp", MaxPathBytes: semanticaction.DefaultWorkspaceMaxPathBytes,
		MaxContentBytes: semanticaction.DefaultWorkspaceMaxContentBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func validWorkspaceInput(raw string) semanticaction.Input {
	return semanticaction.Input{
		PrincipalID: "user-01", AgentID: "workspace-agent", WorkloadID: "workspace-workload-v1",
		DelegatedAuthorityFingerprint: "sha256:" + strings.Repeat("a", 64),
		Tool:                          "workspace.write", Capability: "workspace_write", Resource: "demo-workspace", Operation: "write",
		Arguments: json.RawMessage(raw),
	}
}
