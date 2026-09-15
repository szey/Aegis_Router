package semanticaction

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/szey/Aegis_Router/internal/canonicalaction"
	"github.com/szey/Aegis_Router/internal/models"
)

const PaymentSendV1ID = "payment.send/v1"

const (
	RejectToolUnmapped        RejectionCode = "PAYMENT_TOOL_UNMAPPED"
	RejectBindingConflict     RejectionCode = "PAYMENT_BINDING_CONFLICT"
	RejectProfileMismatch     RejectionCode = "PAYMENT_PROFILE_MISMATCH"
	RejectAudienceMismatch    RejectionCode = "PAYMENT_AUDIENCE_MISMATCH"
	RejectArgumentsInvalid    RejectionCode = "PAYMENT_ARGUMENTS_INVALID"
	RejectAmountInvalid       RejectionCode = "PAYMENT_AMOUNT_INVALID"
	RejectAmountExceedsLimit  RejectionCode = "PAYMENT_AMOUNT_EXCEEDS_LIMIT"
	RejectCurrencyNotAllowed  RejectionCode = "PAYMENT_CURRENCY_NOT_ALLOWED"
	RejectRecipientNotAllowed RejectionCode = "PAYMENT_RECIPIENT_NOT_ALLOWED"
)

type PaymentSendArguments struct {
	AmountMinor int64  `json:"amount_minor"`
	Currency    string `json:"currency"`
	Recipient   string `json:"recipient"`
}

type PaymentSendV1 struct {
	binding    string
	config     models.PaymentSendV1Config
	currencies map[string]int64
	recipients map[string]struct{}
	upstream   *url.URL
}

func NewPaymentSendV1(config models.PaymentSendV1Config) (*PaymentSendV1, error) {
	if config.ProfileID != PaymentSendV1ID || config.MCPTool != "payment.send" ||
		strings.TrimSpace(config.Capability) == "" || strings.TrimSpace(config.Resource) == "" ||
		strings.TrimSpace(config.Operation) == "" || strings.TrimSpace(config.Audience) == "" {
		return nil, fmt.Errorf("invalid %s binding configuration", PaymentSendV1ID)
	}
	upstream, err := url.Parse(strings.TrimSpace(config.UpstreamURL))
	if err != nil || upstream.Scheme == "" || upstream.Host == "" || (upstream.Scheme != "http" && upstream.Scheme != "https") {
		return nil, fmt.Errorf("%s upstream_url must be an absolute HTTP(S) URL", PaymentSendV1ID)
	}
	profile := &PaymentSendV1{config: config, currencies: make(map[string]int64), recipients: make(map[string]struct{}), upstream: upstream}
	for _, currency := range config.AllowedCurrencies {
		if currency == "" || currency != strings.ToUpper(currency) {
			return nil, fmt.Errorf("%s currencies must be non-empty uppercase identifiers", PaymentSendV1ID)
		}
		limit, ok := config.MaxAmountMinorByCurrency[currency]
		if !ok || limit <= 0 {
			return nil, fmt.Errorf("%s currency %s must have a positive minor-unit limit", PaymentSendV1ID, currency)
		}
		if _, duplicate := profile.currencies[currency]; duplicate {
			return nil, fmt.Errorf("%s contains duplicate currency %s", PaymentSendV1ID, currency)
		}
		profile.currencies[currency] = limit
	}
	if len(profile.currencies) == 0 || len(profile.currencies) != len(config.MaxAmountMinorByCurrency) {
		return nil, fmt.Errorf("%s currency allowlist and per-currency limits must match exactly", PaymentSendV1ID)
	}
	for _, recipient := range config.AllowedRecipients {
		if strings.TrimSpace(recipient) == "" || recipient != strings.TrimSpace(recipient) {
			return nil, fmt.Errorf("%s recipients must be non-empty exact identifiers", PaymentSendV1ID)
		}
		if _, duplicate := profile.recipients[recipient]; duplicate {
			return nil, fmt.Errorf("%s contains duplicate recipient %s", PaymentSendV1ID, recipient)
		}
		profile.recipients[recipient] = struct{}{}
	}
	if len(profile.recipients) == 0 {
		return nil, fmt.Errorf("%s must allow at least one recipient", PaymentSendV1ID)
	}
	if upstream.User != nil || upstream.Fragment != "" || upstream.RawQuery != "" || upstream.ForceQuery {
		return nil, fmt.Errorf("%s upstream cannot contain credentials, query, or fragment", PaymentSendV1ID)
	}
	config.UpstreamURL = upstream.String()
	profile.binding, err = executionBinding(config, upstream.String())
	if err != nil {
		return nil, err
	}
	return profile, nil
}

func (p *PaymentSendV1) Tool() string          { return p.config.MCPTool }
func (p *PaymentSendV1) ProfileID() string     { return p.config.ProfileID }
func (p *PaymentSendV1) Audience() string      { return p.config.Audience }
func (p *PaymentSendV1) UpstreamURL() string   { return p.upstream.String() }
func (p *PaymentSendV1) BindingDigest() string { return p.binding }

func (p *PaymentSendV1) Resolve(input Input) (Resolved, error) {
	if p == nil || input.Tool != p.config.MCPTool {
		return Resolved{}, &Rejection{Code: RejectToolUnmapped, Detail: "MCP tool has no server-owned semantic mapping"}
	}
	if input.Capability == "" || input.Resource == "" || input.Operation == "" ||
		input.Capability != p.config.Capability || input.Resource != p.config.Resource || input.Operation != p.config.Operation {
		return Resolved{}, &Rejection{Code: RejectBindingConflict, Detail: "capability, resource, and operation must exactly match the server mapping"}
	}
	if input.ProfileID != "" && input.ProfileID != p.config.ProfileID {
		return Resolved{}, &Rejection{Code: RejectProfileMismatch, Detail: "client profile assertion conflicts with the server mapping"}
	}
	if input.Audience != "" && input.Audience != p.config.Audience {
		return Resolved{}, &Rejection{Code: RejectAudienceMismatch, Detail: "client audience assertion conflicts with the server mapping"}
	}
	arguments, err := p.parseArguments(input.Arguments)
	if err != nil {
		return Resolved{}, err
	}
	normalized, err := json.Marshal(arguments)
	if err != nil {
		return Resolved{}, &Rejection{Code: RejectArgumentsInvalid, Detail: "could not normalize payment arguments"}
	}
	action := canonicalaction.Action{
		PrincipalID: input.PrincipalID, AgentID: input.AgentID, WorkloadID: input.WorkloadID,
		DelegatedAuthorityFingerprint: input.DelegatedAuthorityFingerprint,
		Tool:                          p.config.MCPTool, Capability: p.config.Capability, Resource: p.config.Resource,
		Operation: p.config.Operation, ProfileID: p.config.ProfileID, Audience: p.config.Audience,
		Arguments: normalized,
	}
	return Resolved{Action: action, NormalizedArguments: normalized, UpstreamURL: p.upstream.String(),
		PolicyFacts: PolicyFacts{SideEffect: "financial_transaction", Bytes: int64(len(normalized))}}, nil
}

func (p *PaymentSendV1) parseArguments(raw json.RawMessage) (PaymentSendArguments, error) {
	if _, err := canonicalaction.CanonicalizeJSON(raw); err != nil {
		return PaymentSendArguments{}, &Rejection{Code: RejectArgumentsInvalid, Detail: "arguments must be unambiguous JSON"}
	}
	var wire struct {
		AmountMinor *int64  `json:"amount_minor"`
		Currency    *string `json:"currency"`
		Recipient   *string `json:"recipient"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return PaymentSendArguments{}, &Rejection{Code: RejectArgumentsInvalid, Detail: "only amount_minor, currency, and recipient with exact JSON types are allowed"}
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return PaymentSendArguments{}, &Rejection{Code: RejectArgumentsInvalid, Detail: "trailing JSON is not allowed"}
	}
	if wire.AmountMinor == nil || wire.Currency == nil || wire.Recipient == nil || *wire.Currency == "" || *wire.Recipient == "" {
		return PaymentSendArguments{}, &Rejection{Code: RejectArgumentsInvalid, Detail: "amount_minor, currency, and recipient are required"}
	}
	if *wire.AmountMinor <= 0 {
		return PaymentSendArguments{}, &Rejection{Code: RejectAmountInvalid, Detail: "amount_minor must be a positive integer"}
	}
	limit, ok := p.currencies[*wire.Currency]
	if !ok {
		return PaymentSendArguments{}, &Rejection{Code: RejectCurrencyNotAllowed, Detail: "currency is not on the server allowlist"}
	}
	if *wire.AmountMinor > limit {
		return PaymentSendArguments{}, &Rejection{Code: RejectAmountExceedsLimit, Detail: "amount_minor exceeds the configured limit for this currency"}
	}
	if _, ok := p.recipients[*wire.Recipient]; !ok {
		return PaymentSendArguments{}, &Rejection{Code: RejectRecipientNotAllowed, Detail: "recipient is not on the server allowlist"}
	}
	return PaymentSendArguments{AmountMinor: *wire.AmountMinor, Currency: *wire.Currency, Recipient: *wire.Recipient}, nil
}

func (p *PaymentSendV1) AllowedCurrencies() []string {
	result := make([]string, 0, len(p.currencies))
	for currency := range p.currencies {
		result = append(result, currency)
	}
	sort.Strings(result)
	return result
}
