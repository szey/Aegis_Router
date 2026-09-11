package discovery_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/szey/Aegis_Router/internal/discovery"
)

func TestScannerFindsAndReconcilesShadowAgent(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}`)
	writeFile(t, filepath.Join(root, "mcp.json"), `{"mcpServers":{"ops":{"command":"node"}}}`)

	cfg := discovery.Config{
		MaxFileBytes: 1 << 20,
		Signatures: []discovery.Signature{{
			AgentType: "mcp", DisplayName: "MCP integration",
			FileNames: []string{"mcp.json"}, ContentFiles: []string{"package.json"},
			ContentIndicators: []string{"@modelcontextprotocol/sdk"},
		}},
	}
	report, err := discovery.NewScanner(cfg).Scan([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Shadow != 1 || len(report.Agents) != 1 {
		t.Fatalf("summary = %#v, agents = %d", report.Summary, len(report.Agents))
	}
	agent := report.Agents[0]
	if agent.Status != discovery.StatusShadow {
		t.Fatalf("status = %q, want shadow", agent.Status)
	}
	if len(agent.Evidence) != 2 {
		t.Fatalf("evidence = %d, want 2", len(agent.Evidence))
	}
	if agent.Exposure.Classification != "configured_or_observed_workload" {
		t.Fatalf("exposure = %#v, want configured workload", agent.Exposure)
	}
	if agent.Fingerprint == "" {
		t.Fatal("fingerprint is empty")
	}

	cfg.ApprovedAgents = []discovery.RegistryEntry{{
		Name: "Approved MCP", AgentType: "mcp", PathContains: "mcp.json", Owner: "platform-security",
	}}
	reconciled, err := discovery.NewScanner(cfg).Scan([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	approved := reconciled.Agents[0]
	if approved.Status != discovery.StatusApproved || approved.Owner != "platform-security" {
		t.Fatalf("approved agent = %#v", approved)
	}
	if reconciled.Summary.Approved != 1 || reconciled.Summary.Shadow != 0 {
		t.Fatalf("summary = %#v", reconciled.Summary)
	}
}

func TestDependencyIndicatorAloneIsEvidenceNotShadowWorkload(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "editor-extension", "requirements.txt"), "autogen==1.0.0")
	cfg := discovery.Config{
		Signatures: []discovery.Signature{{
			AgentType: "autogen", DisplayName: "AutoGen",
			ContentFiles: []string{"requirements.txt"}, ContentIndicators: []string{"autogen"},
		}},
	}
	report, err := discovery.NewScanner(cfg).Scan([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Available != 1 || report.Summary.Shadow != 0 {
		t.Fatalf("summary = %#v, dependency presence must not create a Shadow workload", report.Summary)
	}
	finding := report.Agents[0]
	if finding.DeploymentState != discovery.DeploymentAvailable || finding.Exposure.Classification != "discovery_evidence_only" {
		t.Fatalf("finding = %#v, want evidence-only", finding)
	}
	if len(finding.Exposure.PotentialCapabilities) != 1 || finding.Exposure.PotentialCapabilities[0] != "agent_workflow" {
		t.Fatalf("dependency-only potential capabilities = %v", finding.Exposure.PotentialCapabilities)
	}
	encoded, err := json.Marshal(finding)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"risk"`)) || !bytes.Contains(encoded, []byte(`"potential_exposure"`)) {
		t.Fatalf("discovery JSON must expose potential exposure, not runtime risk: %s", encoded)
	}
}

func TestScannerDoesNotCallMarketplaceCatalogEvidenceShadow(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "plugins", "marketplaces", "catalog-agent", "mcp.json"), `{}`)
	cfg := discovery.Config{
		Signatures: []discovery.Signature{{AgentType: "mcp", DisplayName: "MCP", FileNames: []string{"mcp.json"}}},
	}
	report, err := discovery.NewScanner(cfg).Scan([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Available != 1 || report.Summary.Shadow != 0 {
		t.Fatalf("summary = %#v, want one available-only capability", report.Summary)
	}
	if report.Agents[0].DeploymentState != discovery.DeploymentAvailable || report.Agents[0].Status != discovery.StatusUnassessed {
		t.Fatalf("catalog finding = %#v", report.Agents[0])
	}
}

func TestSuspendedOrExpiredApprovalDoesNotReconcile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "mcp.json"), `{}`)
	cfg := discovery.Config{
		ApprovedAgents: []discovery.RegistryEntry{{
			Name: "Old MCP", AgentType: "mcp", PathContains: "mcp.json", Owner: "security", State: "suspended",
		}},
		Signatures: []discovery.Signature{{AgentType: "mcp", DisplayName: "MCP", FileNames: []string{"mcp.json"}}},
	}
	report, err := discovery.NewScanner(cfg).Scan([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Shadow != 1 || report.Summary.Approved != 0 {
		t.Fatalf("summary = %#v, want suspended approval to remain shadow", report.Summary)
	}
}

func TestFingerprintPreventsBroadPathApproval(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "mcp.json"), `{}`)
	cfg := discovery.Config{
		ApprovedAgents: []discovery.RegistryEntry{{
			Name: "Different MCP", AgentType: "mcp", Fingerprint: "sha256:000000000000000000000000",
			PathContains: "mcp.json", Owner: "security",
		}},
		Signatures: []discovery.Signature{{AgentType: "mcp", DisplayName: "MCP", FileNames: []string{"mcp.json"}}},
	}
	report, err := discovery.NewScanner(cfg).Scan([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Shadow != 1 || report.Summary.Approved != 0 {
		t.Fatalf("summary = %#v, mismatched fingerprint must not approve", report.Summary)
	}
}

func TestScannerSkipsConfiguredDirectories(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "node_modules", "mcp.json"), `{}`)
	cfg := discovery.Config{
		SkipDirectories: []string{"node_modules"},
		Signatures:      []discovery.Signature{{AgentType: "mcp", DisplayName: "MCP", FileNames: []string{"mcp.json"}}},
	}
	report, err := discovery.NewScanner(cfg).Scan([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Total != 0 {
		t.Fatalf("found %d agents in skipped directory", report.Summary.Total)
	}
}

func TestScannerKeepsProjectsSeparate(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "alpha", "mcp.json"), `{}`)
	writeFile(t, filepath.Join(root, "beta", "mcp.json"), `{}`)
	cfg := discovery.Config{
		Signatures: []discovery.Signature{{AgentType: "mcp", DisplayName: "MCP", FileNames: []string{"mcp.json"}}},
	}
	report, err := discovery.NewScanner(cfg).Scan([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Total != 2 || report.Summary.Shadow != 2 {
		t.Fatalf("summary = %#v, want two separate Shadow Agents", report.Summary)
	}
	if report.Agents[0].Fingerprint == report.Agents[1].Fingerprint {
		t.Fatal("separate projects received the same fingerprint")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
