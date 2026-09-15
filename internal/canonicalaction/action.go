// Package canonicalaction defines the exact action representation used at
// both authorization and execution time. It intentionally retains only an
// argument digest after canonicalization; callers should not persist raw
// arguments in permits or audit records.
package canonicalaction

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxArgumentsBytes limits work performed before an execution-boundary
	// decision. MCP arguments larger than this must be rejected or reduced by
	// the adapter before authorization.
	MaxArgumentsBytes = 1 << 20
	maxJSONDepth      = 64
)

var (
	ErrInvalidAction      = errors.New("invalid canonical action")
	ErrInvalidJSON        = errors.New("invalid action arguments JSON")
	ErrDuplicateObjectKey = errors.New("duplicate JSON object key")
	ErrArgumentsTooLarge  = errors.New("action arguments exceed size limit")
	jsonNumberPattern     = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)
	fingerprintInput      = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	fingerprintBinding    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Action contains every execution-relevant value bound by an Aegis permit.
// Arguments must contain only the security-relevant arguments selected by the
// adapter. They are canonicalized and hashed, never copied into permit claims.
type Action struct {
	PrincipalID                   string
	AgentID                       string
	WorkloadID                    string
	DelegatedAuthorityFingerprint string
	Tool                          string
	Capability                    string
	Resource                      string
	Operation                     string
	ProfileID                     string
	Audience                      string
	ExecutionBinding              string
	Arguments                     json.RawMessage
}

// Validate rejects incomplete or lossy action identities. Empty delegated
// authority fingerprints are allowed for actions that carry no delegation.
func (a Action) Validate() error {
	fields := []struct {
		name  string
		value string
		limit int
	}{
		{"principal_id", a.PrincipalID, 512},
		{"agent_id", a.AgentID, 512},
		{"workload_id", a.WorkloadID, 512},
		{"tool", a.Tool, 512},
		{"capability", a.Capability, 512},
		{"resource", a.Resource, 2048},
		{"operation", a.Operation, 512},
	}
	for _, field := range fields {
		if field.value == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidAction, field.name)
		}
		if !utf8.ValidString(field.value) || len(field.value) > field.limit || strings.IndexFunc(field.value, unicode.IsControl) >= 0 {
			return fmt.Errorf("%w: %s is invalid or too long", ErrInvalidAction, field.name)
		}
	}
	if a.DelegatedAuthorityFingerprint != "" && !fingerprintBinding.MatchString(a.DelegatedAuthorityFingerprint) {
		return fmt.Errorf("%w: delegated_authority_fingerprint must be an Aegis-bound SHA-256 digest", ErrInvalidAction)
	}
	if a.ExecutionBinding != "" && !fingerprintBinding.MatchString(a.ExecutionBinding) {
		return fmt.Errorf("%w: execution_binding must be a SHA-256 digest", ErrInvalidAction)
	}
	if (a.ProfileID == "") != (a.Audience == "") {
		return fmt.Errorf("%w: profile_id and audience must be present together", ErrInvalidAction)
	}
	if err := validateOptionalMetadata("profile_id", a.ProfileID, 256); err != nil {
		return err
	}
	if err := validateOptionalMetadata("audience", a.Audience, 1024); err != nil {
		return err
	}
	return nil
}

func validateOptionalMetadata(name, value string, limit int) error {
	if value == "" {
		return nil
	}
	if !utf8.ValidString(value) || len(value) > limit || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%w: %s is invalid or too long", ErrInvalidAction, name)
	}
	return nil
}

// BindDelegatedAuthorityFingerprint converts a caller-declared SHA-256
// fingerprint into the value used by CanonicalAction, Permit claims, and
// audit. This defense-in-depth rehash means even a secret accidentally shaped
// like a 64-hex digest is not persisted verbatim.
func BindDelegatedAuthorityFingerprint(input string) (string, error) {
	if input == "" {
		return "", nil
	}
	if !fingerprintInput.MatchString(input) {
		return "", fmt.Errorf("%w: delegated authority input must be a 64-character hex digest", ErrInvalidAction)
	}
	sum := sha256.Sum256([]byte(strings.ToLower(input)))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// CanonicalJSON serializes an action deterministically. Object keys are sorted
// recursively, duplicate object keys are rejected, array order is preserved,
// and JSON numbers are normalized exactly without converting them to float64.
func (a Action) CanonicalJSON() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}

	arguments := bytes.TrimSpace(a.Arguments)
	if len(arguments) == 0 {
		arguments = []byte("{}")
	}
	argumentValue, err := parseJSON(arguments)
	if err != nil {
		return nil, err
	}

	value := map[string]any{
		"agent_id":                        a.AgentID,
		"arguments":                       argumentValue,
		"capability":                      a.Capability,
		"delegated_authority_fingerprint": a.DelegatedAuthorityFingerprint,
		"operation":                       a.Operation,
		"profile_id":                      a.ProfileID,
		"principal_id":                    a.PrincipalID,
		"resource":                        a.Resource,
		"tool":                            a.Tool,
		"audience":                        a.Audience,
		"workload_id":                     a.WorkloadID,
	}

	var output bytes.Buffer
	if a.ExecutionBinding != "" {
		value["execution_binding"] = a.ExecutionBinding
	}
	if err := writeCanonicalJSON(&output, value); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	return output.Bytes(), nil
}

// Digest returns a lowercase, algorithm-qualified SHA-256 action digest.
func (a Action) Digest() (string, error) {
	canonical, err := a.CanonicalJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// CanonicalizeJSON canonicalizes a standalone JSON value using the same rules
// applied to Action.Arguments.
func CanonicalizeJSON(input []byte) ([]byte, error) {
	value, err := parseJSON(bytes.TrimSpace(input))
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := writeCanonicalJSON(&output, value); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	return output.Bytes(), nil
}

type canonicalNumber string

func parseJSON(input []byte) (any, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("%w: empty input", ErrInvalidJSON)
	}
	if len(input) > MaxArgumentsBytes {
		return nil, ErrArgumentsTooLarge
	}
	if err := validateJSONStringEncoding(input); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	value, err := readJSONValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%w: unexpected trailing token %v", ErrInvalidJSON, token)
		}
		return nil, fmt.Errorf("%w: trailing data: %v", ErrInvalidJSON, err)
	}
	return value, nil
}

// encoding/json deliberately replaces malformed UTF-8 and unpaired UTF-16
// surrogate escapes with U+FFFD. At a security boundary that behavior could
// collapse two distinct inputs to one digest, so reject those inputs first.
func validateJSONStringEncoding(input []byte) error {
	if !utf8.Valid(input) {
		return fmt.Errorf("%w: input is not valid UTF-8", ErrInvalidJSON)
	}
	for index := 0; index < len(input); index++ {
		if input[index] != '"' {
			continue
		}
		index++
		for index < len(input) && input[index] != '"' {
			if input[index] != '\\' {
				_, size := utf8.DecodeRune(input[index:])
				index += size
				continue
			}
			index++
			if index >= len(input) {
				return fmt.Errorf("%w: incomplete string escape", ErrInvalidJSON)
			}
			if input[index] != 'u' {
				index++
				continue
			}
			codePoint, next, err := readUTF16Escape(input, index)
			if err != nil {
				return err
			}
			index = next
			if codePoint >= 0xD800 && codePoint <= 0xDBFF {
				if index+2 >= len(input) || input[index] != '\\' || input[index+1] != 'u' {
					return fmt.Errorf("%w: unpaired high-surrogate escape", ErrInvalidJSON)
				}
				low, lowNext, err := readUTF16Escape(input, index+1)
				if err != nil {
					return err
				}
				if low < 0xDC00 || low > 0xDFFF {
					return fmt.Errorf("%w: high surrogate is not followed by a low surrogate", ErrInvalidJSON)
				}
				index = lowNext
			} else if codePoint >= 0xDC00 && codePoint <= 0xDFFF {
				return fmt.Errorf("%w: unpaired low-surrogate escape", ErrInvalidJSON)
			}
		}
	}
	return nil
}

// readUTF16Escape receives the index of the 'u' and returns the index just
// after the four hexadecimal digits.
func readUTF16Escape(input []byte, index int) (uint64, int, error) {
	if index+5 > len(input) {
		return 0, index, fmt.Errorf("%w: incomplete Unicode escape", ErrInvalidJSON)
	}
	value, err := strconv.ParseUint(string(input[index+1:index+5]), 16, 16)
	if err != nil {
		return 0, index, fmt.Errorf("%w: invalid Unicode escape", ErrInvalidJSON)
	}
	return value, index + 5, nil
}

func readJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, fmt.Errorf("%w: maximum nesting depth exceeded", ErrInvalidJSON)
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, fmt.Errorf("%w: object key: %v", ErrInvalidJSON, err)
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("%w: object key is not a string", ErrInvalidJSON)
				}
				if _, exists := object[key]; exists {
					return nil, fmt.Errorf("%w: %q", ErrDuplicateObjectKey, key)
				}
				child, err := readJSONValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				object[key] = child
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return nil, fmt.Errorf("%w: unterminated object", ErrInvalidJSON)
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				child, err := readJSONValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return nil, fmt.Errorf("%w: unterminated array", ErrInvalidJSON)
			}
			return array, nil
		default:
			return nil, fmt.Errorf("%w: unexpected delimiter %q", ErrInvalidJSON, value)
		}
	case json.Number:
		normalized, err := normalizeJSONNumber(string(value))
		if err != nil {
			return nil, err
		}
		return canonicalNumber(normalized), nil
	case string, bool, nil:
		return value, nil
	default:
		return nil, fmt.Errorf("%w: unsupported token type %T", ErrInvalidJSON, token)
	}
}

func normalizeJSONNumber(input string) (string, error) {
	if !jsonNumberPattern.MatchString(input) {
		return "", fmt.Errorf("%w: invalid number %q", ErrInvalidJSON, input)
	}
	negative := strings.HasPrefix(input, "-")
	unsigned := strings.TrimPrefix(input, "-")

	exponent := int64(0)
	if index := strings.IndexAny(unsigned, "eE"); index >= 0 {
		parsed, err := strconv.ParseInt(unsigned[index+1:], 10, 64)
		if err != nil {
			return "", fmt.Errorf("%w: number exponent is out of range", ErrInvalidJSON)
		}
		exponent = parsed
		unsigned = unsigned[:index]
	}
	if exponent < -1_000_000 || exponent > 1_000_000 {
		return "", fmt.Errorf("%w: number exponent is out of range", ErrInvalidJSON)
	}
	if index := strings.IndexByte(unsigned, '.'); index >= 0 {
		fractionDigits := len(unsigned) - index - 1
		if int64(fractionDigits) > 1_000_000 {
			return "", fmt.Errorf("%w: number exponent is out of range", ErrInvalidJSON)
		}
		exponent -= int64(fractionDigits)
		if exponent < -1_000_000 || exponent > 1_000_000 {
			return "", fmt.Errorf("%w: number exponent is out of range", ErrInvalidJSON)
		}
		unsigned = unsigned[:index] + unsigned[index+1:]
	}

	digits := strings.TrimLeft(unsigned, "0")
	if digits == "" {
		return "0", nil
	}
	for len(digits) > 1 && digits[len(digits)-1] == '0' {
		digits = digits[:len(digits)-1]
		exponent++
	}
	if exponent < -1_000_000 || exponent > 1_000_000 {
		return "", fmt.Errorf("%w: number exponent is out of range", ErrInvalidJSON)
	}
	if negative {
		digits = "-" + digits
	}
	if exponent == 0 {
		return digits, nil
	}
	return digits + "e" + strconv.FormatInt(exponent, 10), nil
}

func writeCanonicalJSON(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		if typed {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
	case string:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return err
		}
		output.Write(encoded)
	case canonicalNumber:
		output.WriteString(string(typed))
	case []any:
		output.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := writeCanonicalJSON(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			encodedKey, err := json.Marshal(key)
			if err != nil {
				return err
			}
			output.Write(encodedKey)
			output.WriteByte(':')
			if err := writeCanonicalJSON(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON value %T", value)
	}
	return nil
}
