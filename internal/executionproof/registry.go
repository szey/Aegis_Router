package executionproof

import (
	"crypto/ed25519"
	"fmt"
	"sync"

	"agent-governance-gateway/internal/keyprovider"
)

// Registry is the server-owned Ed25519 public-key registry used at the MCP
// boundary. The proof's untrusted kid never causes fallback to another key.
type Registry struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey
}

func NewRegistry() *Registry { return &Registry{keys: make(map[string]ed25519.PublicKey)} }

func (registry *Registry) Register(keyID string, publicKey ed25519.PublicKey) error {
	if registry == nil {
		return fmt.Errorf("execution proof registry is nil")
	}
	if err := keyprovider.ValidateKeyID(keyID); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return keyprovider.ErrInvalidKey
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if existing, ok := registry.keys[keyID]; ok && string(existing) != string(publicKey) {
		return fmt.Errorf("execution proof key id %q is already registered to another key", keyID)
	}
	registry.keys[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	return nil
}

func (registry *Registry) VerificationKey(keyID string) (ed25519.PublicKey, error) {
	if registry == nil {
		return nil, keyprovider.ErrUnknownKeyID
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	key, ok := registry.keys[keyID]
	if !ok {
		return nil, keyprovider.ErrUnknownKeyID
	}
	return append(ed25519.PublicKey(nil), key...), nil
}

// NonceStore atomically rejects a second use of the same workload-key nonce.
// Entries expire after the proof freshness window.
type NonceStore struct {
	mu      sync.Mutex
	expires map[string]int64
}

func NewNonceStore() *NonceStore { return &NonceStore{expires: make(map[string]int64)} }

func (store *NonceStore) Use(keyID, nonce string, nowUnix, expiresUnix int64) bool {
	if store == nil || keyID == "" || nonce == "" || expiresUnix <= nowUnix {
		return false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for key, expires := range store.expires {
		if expires <= nowUnix {
			delete(store.expires, key)
		}
	}
	key := keyID + "\x00" + nonce
	if _, exists := store.expires[key]; exists {
		return false
	}
	store.expires[key] = expiresUnix
	return true
}
