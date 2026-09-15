package permit

import (
	"fmt"
	"math"
	"time"
)

// AuthorityKey identifies the principal/agent/workload grant domain. It is
// supplied by trusted control-plane code, never by the execution request.
type AuthorityKey struct {
	PrincipalID string
	AgentID     string
	WorkloadID  string
}

type AuthorityState struct {
	Epoch   uint64
	Enabled bool
}

func (c Claims) AuthorityKey() AuthorityKey {
	return AuthorityKey{PrincipalID: c.PrincipalID, AgentID: c.AgentID, WorkloadID: c.WorkloadID}
}

func (s *MemoryStore) authorityLocked(key AuthorityKey) AuthorityState {
	if state, ok := s.authorities[key]; ok {
		return state
	}
	return AuthorityState{Epoch: 1, Enabled: true}
}

func (s *MemoryStore) Authority(key AuthorityKey) AuthorityState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authorityLocked(key)
}

// SetAuthorityEnabled is the revocation linearization point. It always rotates
// the epoch, including enabled→enabled policy refreshes. Register and Consume
// check the same state under the same mutex. Already-consumed work stays in
// flight; neither revocation nor re-enabling can restore an old Permit.
// This store is process-local, not a durable IAM or distributed transaction.
func (s *MemoryStore) SetAuthorityEnabled(key AuthorityKey, enabled bool, at time.Time) (AuthorityState, error) {
	for name, value := range map[string]string{"principal": key.PrincipalID, "agent": key.AgentID, "workload": key.WorkloadID} {
		if err := validateMetadata(name, value, 512, true); err != nil {
			return AuthorityState{}, err
		}
	}
	if at.IsZero() {
		return AuthorityState{}, fmt.Errorf("authority transition requires a timestamp")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.authorityLocked(key)
	if state.Epoch == math.MaxUint64 {
		return state, fmt.Errorf("authority epoch exhausted")
	}
	state.Epoch++
	state.Enabled = enabled
	if s.authorities == nil {
		s.authorities = make(map[AuthorityKey]AuthorityState)
	}
	s.authorities[key] = state
	for id, record := range s.records {
		if record.State == StateIssued && record.Claims.PermitClass == ClassExecution && record.Claims.AuthorityKey() == key {
			revokedAt := at.UTC()
			record.State, record.RevokedAt = StateRevoked, &revokedAt
			s.records[id] = record
		}
	}
	return state, nil
}
