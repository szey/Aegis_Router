package permit

import (
	"errors"
	"sort"
	"sync"
	"time"
)

type State string

const (
	StateIssued   State = "ISSUED"
	StateConsumed State = "CONSUMED"
	StateExpired  State = "EXPIRED"
	StateRevoked  State = "REVOKED"
)

var (
	ErrPermitExists     = errors.New("execution permit already exists")
	ErrPermitNotFound   = errors.New("execution permit not found")
	ErrPermitNotActive  = errors.New("execution permit is not active")
	ErrAuthorityChanged = errors.New("execution authority is disabled or its epoch changed")
)

// Record is safe to list or audit: it never contains the execution credential
// or raw arguments.
type Record struct {
	Claims     Claims     `json:"claims"`
	State      State      `json:"state"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
	ExpiredAt  *time.Time `json:"expired_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

type ConsumeOutcome string

const (
	ConsumeSucceeded ConsumeOutcome = "CONSUMED"
	ConsumeExpired   ConsumeOutcome = "EXPIRED"
	ConsumeReplayed  ConsumeOutcome = "REPLAYED"
	ConsumeRevoked   ConsumeOutcome = "REVOKED"
	ConsumeUnknown   ConsumeOutcome = "UNKNOWN"
)

type ConsumeResult struct {
	Outcome ConsumeOutcome
	Record  Record
}

// Store is the atomic lifecycle boundary used by the verifier.
type Store interface {
	Authority(key AuthorityKey) AuthorityState
	SetAuthorityEnabled(key AuthorityKey, enabled bool, at time.Time) (AuthorityState, error)
	Register(claims Claims) error
	Get(permitID string, now time.Time) (Record, bool)
	List(now time.Time) []Record
	Consume(permitID string, now time.Time) ConsumeResult
	Revoke(permitID string, at time.Time) (Record, error)
}

// MemoryStore is a concurrency-safe MVP replay guard. Production deployments
// with more than one verifier process require a shared atomic store.
type MemoryStore struct {
	mu          sync.Mutex
	records     map[string]Record
	authorities map[AuthorityKey]AuthorityState
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]Record)}
}

func (s *MemoryStore) Register(claims Claims) error {
	if err := claims.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = make(map[string]Record)
	}
	if _, exists := s.records[claims.PermitID]; exists {
		return ErrPermitExists
	}
	if claims.ExecutionBinding != "" {
		authority := s.authorityLocked(claims.AuthorityKey())
		if !authority.Enabled || claims.AuthorityEpoch != authority.Epoch {
			return ErrAuthorityChanged
		}
	}
	s.records[claims.PermitID] = Record{Claims: claims, State: StateIssued}
	return nil
}

func (s *MemoryStore) Get(permitID string, now time.Time) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.records[permitID]
	if !exists {
		return Record{}, false
	}
	record = expireIfNeeded(record, now)
	s.records[permitID] = record
	return cloneRecord(record), true
}

func (s *MemoryStore) List(now time.Time) []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]Record, 0, len(s.records))
	for permitID, record := range s.records {
		record = expireIfNeeded(record, now)
		s.records[permitID] = record
		records = append(records, cloneRecord(record))
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Claims.IssuedAt == records[j].Claims.IssuedAt {
			return records[i].Claims.PermitID < records[j].Claims.PermitID
		}
		return records[i].Claims.IssuedAt > records[j].Claims.IssuedAt
	})
	return records
}

func (s *MemoryStore) Consume(permitID string, now time.Time) ConsumeResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.records[permitID]
	if !exists {
		return ConsumeResult{Outcome: ConsumeUnknown}
	}
	record = expireIfNeeded(record, now)
	switch record.State {
	case StateIssued:
		if record.Claims.ExecutionBinding != "" {
			authority := s.authorityLocked(record.Claims.AuthorityKey())
			if !authority.Enabled || record.Claims.AuthorityEpoch != authority.Epoch {
				at := now.UTC()
				record.State, record.RevokedAt = StateRevoked, &at
				s.records[permitID] = record
				return ConsumeResult{Outcome: ConsumeRevoked, Record: cloneRecord(record)}
			}
		}
		at := now.UTC()
		record.State = StateConsumed
		record.ConsumedAt = &at
		s.records[permitID] = record
		return ConsumeResult{Outcome: ConsumeSucceeded, Record: cloneRecord(record)}
	case StateConsumed:
		return ConsumeResult{Outcome: ConsumeReplayed, Record: cloneRecord(record)}
	case StateExpired:
		s.records[permitID] = record
		return ConsumeResult{Outcome: ConsumeExpired, Record: cloneRecord(record)}
	case StateRevoked:
		return ConsumeResult{Outcome: ConsumeRevoked, Record: cloneRecord(record)}
	default:
		return ConsumeResult{Outcome: ConsumeUnknown, Record: cloneRecord(record)}
	}
}

func (s *MemoryStore) Revoke(permitID string, at time.Time) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.records[permitID]
	if !exists {
		return Record{}, ErrPermitNotFound
	}
	record = expireIfNeeded(record, at)
	if record.State != StateIssued {
		s.records[permitID] = record
		return cloneRecord(record), ErrPermitNotActive
	}
	revokedAt := at.UTC()
	record.State = StateRevoked
	record.RevokedAt = &revokedAt
	s.records[permitID] = record
	return cloneRecord(record), nil
}

func expireIfNeeded(record Record, now time.Time) Record {
	if record.State != StateIssued || now.IsZero() {
		return record
	}
	expiresAt := record.Claims.ExpiresTime()
	if !now.UTC().Before(expiresAt) {
		record.State = StateExpired
		record.ExpiredAt = &expiresAt
	}
	return record
}

func cloneRecord(record Record) Record {
	clone := record
	if record.ConsumedAt != nil {
		value := *record.ConsumedAt
		clone.ConsumedAt = &value
	}
	if record.ExpiredAt != nil {
		value := *record.ExpiredAt
		clone.ExpiredAt = &value
	}
	if record.RevokedAt != nil {
		value := *record.RevokedAt
		clone.RevokedAt = &value
	}
	return clone
}
