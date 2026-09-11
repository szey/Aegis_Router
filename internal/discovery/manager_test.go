package discovery_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/szey/Aegis_Router/internal/discovery"
)

func TestManagerPersistsApprovalsAndReconcilesOnChange(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "mcp.json"), `{}`)
	configPath := filepath.Join(t.TempDir(), "discovery.json")
	writeFile(t, configPath, `{
		"signatures":[{"agent_type":"mcp","display_name":"MCP","file_names":["mcp.json"]}]
	}`)
	registryPath := filepath.Join(t.TempDir(), "approved-agents.json")

	manager, err := discovery.NewManager(configPath, registryPath, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	if manager.Report().Summary.Shadow != 1 {
		t.Fatalf("initial summary = %#v", manager.Report().Summary)
	}

	entry, report, err := manager.SaveApproval(discovery.RegistryEntry{
		Name: "Approved MCP", AgentType: "mcp", PathContains: "mcp.json", Owner: "security", ApprovalRef: "CHG-42",
	})
	if err != nil {
		t.Fatal(err)
	}
	if entry.ID == "" || report.Summary.Approved != 1 || report.Summary.Shadow != 0 {
		t.Fatalf("saved entry = %#v, summary = %#v", entry, report.Summary)
	}
	if _, err := os.Stat(registryPath); err != nil {
		t.Fatalf("registry was not persisted: %v", err)
	}

	reloaded, err := discovery.NewManager(configPath, registryPath, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Report().Summary.Approved != 1 || len(reloaded.Registry()) != 1 {
		t.Fatalf("reloaded state = %#v, %#v", reloaded.Report().Summary, reloaded.Registry())
	}

	entry.State = "suspended"
	if _, report, err = reloaded.SaveApproval(entry); err != nil {
		t.Fatal(err)
	}
	if report.Summary.Shadow != 1 {
		t.Fatalf("suspended summary = %#v", report.Summary)
	}
	if report, err = reloaded.DeleteApproval(entry.ID); err != nil {
		t.Fatal(err)
	}
	if report.Summary.Shadow != 1 || len(reloaded.Registry()) != 0 {
		t.Fatalf("deleted state = %#v, %#v", report.Summary, reloaded.Registry())
	}
}
