package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/szey/Aegis_Router/internal/adapters/mcp"
	"github.com/szey/Aegis_Router/internal/audit"
	"github.com/szey/Aegis_Router/internal/config"
	"github.com/szey/Aegis_Router/internal/discovery"
	"github.com/szey/Aegis_Router/internal/executionproof"
	"github.com/szey/Aegis_Router/internal/httpapi"
	"github.com/szey/Aegis_Router/internal/intake"
	"github.com/szey/Aegis_Router/internal/router"
	"github.com/szey/Aegis_Router/internal/scenario"
	"github.com/szey/Aegis_Router/web"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "HTTP listen address")
	policyPath := flag.String("policy", "configs/policy.json", "policy configuration path")
	scenarioPath := flag.String("scenarios", "examples", "demo scenario directory")
	auditPath := flag.String("audit", "data/audit.jsonl", "append-only audit log path")
	sessionAuditPath := flag.String("session-audit", "data/session-audit.jsonl", "local Agent session audit path")
	discoveryConfig := flag.String("discovery-config", "configs/discovery.json", "discovery signature and registry path")
	approvalRegistry := flag.String("approval-registry", "data/approved-agents.json", "local approved-Agent registry managed by the control desk")
	enableExperimentalInventory := flag.Bool("enable-experimental-inventory", false, "enable frozen experimental inventory APIs and UI")
	mcpUpstream := flag.String("mcp-upstream", "", "enable permit-gated POST /mcp; value must match a server-owned semantic upstream and is used for protocol setup passthrough")
	allowDevelopmentIntake := flag.Bool("allow-development-intake", false, "accept caller-supplied authorization identity from loopback requests only (development only)")
	var discoveryRoots stringList
	var trustedProxyCIDRs strictStringList
	var workloadPublicKeys strictStringList
	flag.Var(&discoveryRoots, "discovery-root", "optional approved inventory root; repeat for multiple roots")
	flag.Var(&trustedProxyCIDRs, "trusted-proxy-cidr", "direct TCP peer CIDR trusted to assert authorization identity; repeat for multiple IPv4/IPv6 CIDRs")
	flag.Var(&workloadPublicKeys, "workload-public-key", "registered executor Ed25519 public key as key-id=base64url; repeat for multiple workloads")
	trustedProxyProviderID := flag.String("trusted-proxy-provider-id", "", "identity provider ID recorded for trusted-proxy authorization provenance")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load(*policyPath)
	if err != nil {
		logger.Error("load policy", "error", err)
		os.Exit(1)
	}
	scenarios, err := scenario.LoadDirectory(*scenarioPath)
	if err != nil {
		logger.Error("load scenarios", "error", err)
		os.Exit(1)
	}
	store, err := audit.NewStore(*auditPath)
	if err != nil {
		logger.Error("open audit store", "error", err)
		os.Exit(1)
	}
	var discoveryManager *discovery.Manager
	if *enableExperimentalInventory {
		discoveryManager, err = discovery.NewManager(*discoveryConfig, *approvalRegistry, discoveryRoots)
		if err != nil {
			logger.Error("load experimental inventory", "error", err)
			os.Exit(1)
		}
	}

	r := router.New(cfg, store)
	workloadBindings, keyErr := registerWorkloadPublicKeys(r, workloadPublicKeys)
	if keyErr != nil {
		logger.Error("configure workload execution-proof keys", "error", keyErr)
		os.Exit(1)
	}
	var developmentBinding []intake.WorkloadBinding
	if *allowDevelopmentIntake {
		if len(workloadBindings) != 1 {
			logger.Error("configure authorization intake", "error", "--allow-development-intake requires exactly one --workload-public-key")
			os.Exit(1)
		}
		developmentBinding = workloadBindings
	}
	authorizationIntake, authorizationIntakeMode, intakeErr := configureAuthorizationIntake(*allowDevelopmentIntake, trustedProxyCIDRs, *trustedProxyProviderID, developmentBinding...)
	if intakeErr != nil {
		logger.Error("configure authorization intake", "error", intakeErr)
		os.Exit(1)
	}
	var mcpHandler http.Handler
	if strings.TrimSpace(*mcpUpstream) != "" {
		if len(workloadBindings) == 0 {
			logger.Error("configure MCP enforcement adapter", "error", "--mcp-upstream requires at least one --workload-public-key")
			os.Exit(1)
		}
		proxy, proxyErr := mcp.New(r, r.SemanticRegistry(), strings.TrimSpace(*mcpUpstream), nil)
		if proxyErr != nil {
			logger.Error("configure MCP enforcement adapter", "error", proxyErr)
			os.Exit(1)
		}
		mcpHandler = proxy
	}
	api := httpapi.NewWithOptions(r, store, cfg, scenarios, discoveryManager, *sessionAuditPath, web.Assets(), logger, httpapi.Options{
		ExperimentalInventory: *enableExperimentalInventory,
		MCPHandler:            mcpHandler,
		AuthorizationIntake:   authorizationIntake,
	})
	server := &http.Server{
		Addr:              *addr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	logger.Info("Aegis_Router listening", "address", *addr, "mcp_enforcement", mcpHandler != nil, "experimental_inventory", *enableExperimentalInventory, "authorization_intake", authorizationIntakeMode)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func configureAuthorizationIntake(allowDevelopment bool, trustedProxyCIDRs []string, trustedProxyProviderID string, developmentBinding ...intake.WorkloadBinding) (intake.TrustedAuthorizationIntake, string, error) {
	trustedProxyConfigured := len(trustedProxyCIDRs) > 0 || trustedProxyProviderID != ""
	if allowDevelopment && trustedProxyConfigured {
		return nil, "", fmt.Errorf("--allow-development-intake cannot be combined with trusted-proxy configuration")
	}
	if allowDevelopment {
		if len(developmentBinding) != 1 {
			return nil, "", fmt.Errorf("--allow-development-intake requires exactly one workload binding")
		}
		provider, err := intake.NewLoopbackDevelopment("server-loopback-development", developmentBinding...)
		return provider, "loopback_development", err
	}
	if trustedProxyConfigured {
		provider, err := intake.NewTrustedProxy(trustedProxyCIDRs, trustedProxyProviderID)
		return provider, "trusted_proxy", err
	}
	return intake.RejectAll{}, "reject_all", nil
}

func registerWorkloadPublicKeys(r *router.Router, values []string) ([]intake.WorkloadBinding, error) {
	bindings := make([]intake.WorkloadBinding, 0, len(values))
	for _, value := range values {
		keyID, encodedKey, found := strings.Cut(value, "=")
		if !found || keyID == "" || encodedKey == "" {
			return nil, fmt.Errorf("workload public key must use key-id=base64url format")
		}
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(encodedKey)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("workload public key %q must contain exactly %d Ed25519 bytes encoded as unpadded base64url", keyID, ed25519.PublicKeySize)
		}
		publicKey := ed25519.PublicKey(decoded)
		if err := r.RegisterWorkloadPublicKey(keyID, publicKey); err != nil {
			return nil, err
		}
		thumbprint, err := executionproof.Thumbprint(publicKey)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, intake.WorkloadBinding{KeyID: keyID, PublicKeyThumbprint: thumbprint})
	}
	return bindings, nil
}

type stringList []string

func (values *stringList) String() string {
	return strings.Join(*values, ",")
}

func (values *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value != "" {
		*values = append(*values, value)
	}
	return nil
}

type strictStringList []string

func (values *strictStringList) String() string {
	return strings.Join(*values, ",")
}

func (values *strictStringList) Set(value string) error {
	if value == "" || value != strings.TrimSpace(value) {
		return fmt.Errorf("value must be non-empty and contain no surrounding whitespace")
	}
	*values = append(*values, value)
	return nil
}
