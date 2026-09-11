package intake

import (
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"agent-governance-gateway/internal/models"
)

const (
	HeaderAuthenticatedPrincipal = "X-Aegis-Authenticated-Principal"
	HeaderAgentID                = "X-Aegis-Agent-Id"
	HeaderWorkloadID             = "X-Aegis-Workload-Id"
	HeaderDelegatedScopes        = "X-Aegis-Delegated-Scopes"
	HeaderDelegationFingerprint  = "X-Aegis-Delegation-Fingerprint"
	HeaderWorkloadKeyID          = "X-Aegis-Workload-Key-Id"
	HeaderWorkloadKeyThumbprint  = "X-Aegis-Workload-Key-Thumbprint"

	maxIdentityHeaderBytes = 128
	maxScopesHeaderBytes   = 4096
	maxDelegatedScopes     = 64
)

var fingerprintPattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

// TrustedProxy consumes identity asserted by a separately authenticated
// reverse proxy. Trust in that assertion is based only on the direct TCP peer
// in http.Request.RemoteAddr; forwarded-address headers are never consulted.
type TrustedProxy struct {
	trustedPeers []netip.Prefix
	providerID   string
	clock        func() time.Time
}

// NewTrustedProxy configures a production-shaped authorization intake. Each
// CIDR may contain an IPv4 or IPv6 direct peer. This component does not
// authenticate users or tokens; it accepts identity from the configured
// external authentication boundary.
func NewTrustedProxy(cidrs []string, providerID string) (*TrustedProxy, error) {
	if providerID != strings.TrimSpace(providerID) || !safeProviderID(providerID) {
		return nil, fmt.Errorf("%w: trusted proxy provider id is missing or invalid", ErrTrustedContextRequired)
	}
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("%w: at least one trusted proxy CIDR is required", ErrTrustedContextRequired)
	}
	trustedPeers := make([]netip.Prefix, 0, len(cidrs))
	seen := make(map[string]struct{}, len(cidrs))
	for _, raw := range cidrs {
		if raw == "" || raw != strings.TrimSpace(raw) {
			return nil, fmt.Errorf("%w: trusted proxy CIDR is empty or contains surrounding whitespace", ErrTrustedContextRequired)
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid trusted proxy CIDR %q", ErrTrustedContextRequired, raw)
		}
		prefix = prefix.Masked()
		key := prefix.String()
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("%w: duplicate trusted proxy CIDR %q", ErrTrustedContextRequired, key)
		}
		seen[key] = struct{}{}
		trustedPeers = append(trustedPeers, prefix)
	}
	return &TrustedProxy{trustedPeers: trustedPeers, providerID: providerID, clock: time.Now}, nil
}

func (provider *TrustedProxy) Resolve(request *http.Request, proposal models.Request) (Authorization, error) {
	if provider == nil || request == nil || len(provider.trustedPeers) == 0 || provider.providerID == "" {
		return Authorization{}, ErrTrustedContextRequired
	}
	peer, err := directPeerAddress(request.RemoteAddr)
	if err != nil {
		return Authorization{}, fmt.Errorf("%w: direct proxy peer cannot be established", ErrTrustedContextRequired)
	}
	if !provider.trusts(peer) {
		return Authorization{}, fmt.Errorf("%w: direct peer is outside the configured trusted proxy CIDR", ErrTrustedContextRequired)
	}

	principalID, err := strictIdentityHeader(request.Header, HeaderAuthenticatedPrincipal)
	if err != nil {
		return Authorization{}, err
	}
	agentID, err := strictIdentityHeader(request.Header, HeaderAgentID)
	if err != nil {
		return Authorization{}, err
	}
	workloadID, err := strictIdentityHeader(request.Header, HeaderWorkloadID)
	if err != nil {
		return Authorization{}, err
	}
	scopesValue, err := singleHeader(request.Header, HeaderDelegatedScopes, maxScopesHeaderBytes)
	if err != nil {
		return Authorization{}, err
	}
	scopes, err := parseDelegatedScopes(scopesValue)
	if err != nil {
		return Authorization{}, err
	}
	fingerprint, err := singleHeader(request.Header, HeaderDelegationFingerprint, 64)
	if err != nil {
		return Authorization{}, err
	}
	if !fingerprintPattern.MatchString(fingerprint) {
		return Authorization{}, fmt.Errorf("%w: %s must be a 64-character hexadecimal SHA-256 fingerprint", ErrTrustedContextRequired, HeaderDelegationFingerprint)
	}
	workloadKeyID, err := strictIdentityHeader(request.Header, HeaderWorkloadKeyID)
	if err != nil {
		return Authorization{}, err
	}
	workloadKeyThumbprint, err := singleHeader(request.Header, HeaderWorkloadKeyThumbprint, 71)
	if err != nil {
		return Authorization{}, err
	}
	workloadBinding := WorkloadBinding{KeyID: workloadKeyID, PublicKeyThumbprint: workloadKeyThumbprint}
	if err := validateWorkloadBinding(workloadBinding); err != nil {
		return Authorization{}, err
	}

	identity := IdentityContext{
		Principal: models.PrincipalContext{PrincipalID: principalID, PrincipalType: "human"},
		Agent:     models.AgentIdentity{AgentID: agentID, WorkloadID: workloadID},
		DelegatedAuthority: models.DelegatedAuthority{
			CredentialFingerprint: fingerprint,
			Issuer:                provider.providerID,
			Scopes:                scopes,
			Subject:               principalID,
		},
		WorkloadBinding: workloadBinding,
	}
	return NewTrustedAuthorization(proposal, identity, provider.providerID, provider.clock())
}

func (provider *TrustedProxy) trusts(peer netip.Addr) bool {
	for _, prefix := range provider.trustedPeers {
		if prefix.Contains(peer) || (peer.Is4In6() && prefix.Contains(peer.Unmap())) {
			return true
		}
	}
	return false
}

func directPeerAddress(remoteAddress string) (netip.Addr, error) {
	if remoteAddress == "" || remoteAddress != strings.TrimSpace(remoteAddress) {
		return netip.Addr{}, fmt.Errorf("invalid remote address")
	}
	addressPort, err := netip.ParseAddrPort(remoteAddress)
	if err != nil {
		return netip.Addr{}, err
	}
	address := addressPort.Addr()
	if address.Zone() != "" {
		address = address.WithZone("")
	}
	return address, nil
}

func strictIdentityHeader(header http.Header, name string) (string, error) {
	value, err := singleHeader(header, name, maxIdentityHeaderBytes)
	if err != nil {
		return "", err
	}
	if value != strings.TrimSpace(value) || !safeIdentityLabel(value) {
		return "", fmt.Errorf("%w: %s must be an exact metadata identifier without surrounding whitespace", ErrTrustedContextRequired, name)
	}
	return value, nil
}

func singleHeader(header http.Header, name string, maxBytes int) (string, error) {
	values := header.Values(name)
	if len(values) != 1 {
		return "", fmt.Errorf("%w: %s must occur exactly once", ErrTrustedContextRequired, name)
	}
	value := values[0]
	if value == "" || len(value) > maxBytes {
		return "", fmt.Errorf("%w: %s is empty or oversized", ErrTrustedContextRequired, name)
	}
	return value, nil
}

func parseDelegatedScopes(value string) ([]string, error) {
	parts := strings.Split(value, ",")
	if len(parts) == 0 || len(parts) > maxDelegatedScopes {
		return nil, fmt.Errorf("%w: %s contains no scopes or too many scopes", ErrTrustedContextRequired, HeaderDelegatedScopes)
	}
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		// SP and HTAB are the only separators normalized around commas. Other
		// whitespace remains part of the value and fails the identifier grammar.
		scope := strings.Trim(part, " \t")
		if !safeIdentityLabel(scope) {
			return nil, fmt.Errorf("%w: %s contains an empty or invalid scope", ErrTrustedContextRequired, HeaderDelegatedScopes)
		}
		if _, duplicate := seen[scope]; duplicate {
			return nil, fmt.Errorf("%w: %s contains duplicate scope %q", ErrTrustedContextRequired, HeaderDelegatedScopes, scope)
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}
	sort.Strings(result)
	return result, nil
}

func safeIdentityLabel(value string) bool {
	if value == "" || len(value) > maxIdentityHeaderBytes {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("._:-", char) {
			continue
		}
		return false
	}
	return true
}
