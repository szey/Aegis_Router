package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/szey/Aegis_Router/internal/discovery"
)

type pathsFlag []string

func (p *pathsFlag) String() string { return fmt.Sprint([]string(*p)) }
func (p *pathsFlag) Set(value string) error {
	*p = append(*p, value)
	return nil
}

func main() {
	var paths pathsFlag
	configPath := flag.String("config", "configs/discovery.json", "discovery signatures and registry path")
	registryPath := flag.String("approval-registry", "data/approved-agents.json", "approved-Agent registry path; falls back to config when absent")
	format := flag.String("format", "table", "output format: table or json")
	flag.Var(&paths, "path", "directory to scan; repeat for multiple roots")
	flag.Parse()
	if len(paths) == 0 {
		paths = []string{"."}
	}

	cfg, err := discovery.LoadConfig(*configPath)
	if err != nil {
		fail(err)
	}
	approved, err := discovery.LoadRegistry(*registryPath, cfg.ApprovedAgents)
	if err != nil {
		fail(err)
	}
	cfg.ApprovedAgents = approved
	report, err := discovery.NewScanner(cfg).Scan(paths)
	if err != nil {
		fail(err)
	}

	switch *format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			fail(err)
		}
	case "table":
		writer := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "STATUS\tDEPLOYMENT\tPOTENTIAL EXPOSURE\tCONFIDENCE\tTYPE\tNAME\tEVIDENCE")
		for _, agent := range report.Agents {
			exposure := agent.Exposure.Classification
			if len(agent.Exposure.PotentialCapabilities) > 0 {
				exposure += ":" + strings.Join(agent.Exposure.PotentialCapabilities, ",")
			}
			fmt.Fprintf(writer, "%s\t%s\t%s\t%.0f%%\t%s\t%s\t%d\n", agent.Status, agent.DeploymentState, exposure, agent.Confidence*100, agent.AgentType, agent.Name, len(agent.Evidence))
		}
		_ = writer.Flush()
		fmt.Printf("\nTotal: %d  Approved: %d  Shadow: %d  Available only: %d  Coverage gaps: %d\n", report.Summary.Total, report.Summary.Approved, report.Summary.Shadow, report.Summary.Available, report.Summary.CoverageGaps)
	default:
		fail(fmt.Errorf("unsupported format %q; use table or json", *format))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "discovery failed:", err)
	os.Exit(1)
}
