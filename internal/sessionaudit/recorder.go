package sessionaudit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	SourceAgentJSONL  = "agent-jsonl"
	TrustSelfReported = "self_reported"
	TrustObserver     = "observer_recorded"
)

// Event is the privacy-preserving envelope written by the local session
// observer. Agent-emitted payloads are hashed rather than copied into the
// audit log because commands and tool arguments can contain source code,
// prompts, tokens, or customer data.
type Event struct {
	SchemaVersion string    `json:"schema_version"`
	SessionID     string    `json:"session_id"`
	Sequence      int64     `json:"sequence"`
	ObservedAt    time.Time `json:"observed_at"`
	Source        string    `json:"source"`
	Trust         string    `json:"trust"`
	EventType     string    `json:"event_type"`
	ActionClass   string    `json:"action_class"`
	ObjectType    string    `json:"object_type,omitempty"`
	SourceEventID string    `json:"source_event_id,omitempty"`
	Status        string    `json:"status,omitempty"`
	ExitCode      *int      `json:"exit_code,omitempty"`
	PayloadSHA256 string    `json:"payload_sha256,omitempty"`
	Details       []string  `json:"details,omitempty"`
}

type Recorder struct {
	mu        sync.Mutex
	file      *os.File
	writer    *bufio.Writer
	sessionID string
	sequence  int64
	clock     func() time.Time
}

func New(path, sessionID string) (*Recorder, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("audit path is required")
	}
	if strings.TrimSpace(sessionID) == "" {
		return nil, fmt.Errorf("session ID is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit file: %w", err)
	}
	return &Recorder{
		file:      file,
		writer:    bufio.NewWriter(file),
		sessionID: sessionID,
		clock:     time.Now,
	}, nil
}

func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.writer.Flush(); err != nil {
		_ = r.file.Close()
		return err
	}
	return r.file.Close()
}

func (r *Recorder) RecordLifecycle(eventType, status string, details []string) (Event, error) {
	event := Event{
		Source:      "aegis-router-observer",
		Trust:       TrustObserver,
		EventType:   eventType,
		ActionClass: "process.lifecycle",
		Status:      status,
		Details:     details,
	}
	return r.append(event)
}

func (r *Recorder) RecordJSONLine(line []byte) (Event, error) {
	event := normalizeJSONLine(line)
	return r.append(event)
}

func (r *Recorder) append(event Event) (Event, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sequence++
	event.SchemaVersion = "aegis-router.session-event.v1"
	event.SessionID = r.sessionID
	event.Sequence = r.sequence
	event.ObservedAt = r.clock().UTC()
	if err := json.NewEncoder(r.writer).Encode(event); err != nil {
		return Event{}, err
	}
	if err := r.writer.Flush(); err != nil {
		return Event{}, err
	}
	return event, nil
}

type incomingEvent struct {
	Type     string       `json:"type"`
	ThreadID string       `json:"thread_id"`
	Item     incomingItem `json:"item"`
}

type incomingItem struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Status   string `json:"status"`
	ExitCode *int   `json:"exit_code"`
}

func normalizeJSONLine(line []byte) Event {
	sum := sha256.Sum256(line)
	event := Event{
		Source:        SourceAgentJSONL,
		Trust:         TrustSelfReported,
		EventType:     "unparsed",
		ActionClass:   "agent.event",
		PayloadSHA256: hex.EncodeToString(sum[:]),
	}
	var incoming incomingEvent
	if err := json.Unmarshal(line, &incoming); err != nil {
		event.Status = "invalid_json"
		return event
	}
	if incoming.Type != "" {
		event.EventType = incoming.Type
	}
	event.ObjectType = incoming.Item.Type
	event.SourceEventID = incoming.Item.ID
	event.Status = incoming.Item.Status
	event.ExitCode = incoming.Item.ExitCode
	if incoming.ThreadID != "" {
		event.Details = append(event.Details, "source_thread_id="+incoming.ThreadID)
	}
	event.ActionClass = classify(incoming.Type, incoming.Item.Type)
	return event
}

func classify(eventType, itemType string) string {
	switch itemType {
	case "command_execution":
		return "process.exec"
	case "mcp_tool_call", "tool_call":
		return "tool.call"
	case "file_change":
		return "file.change"
	case "web_search", "web_search_call":
		return "network.search"
	case "agent_message", "reasoning":
		return "agent.output"
	}
	if strings.HasPrefix(eventType, "thread.") || strings.HasPrefix(eventType, "turn.") {
		return "agent.lifecycle"
	}
	if eventType == "error" {
		return "agent.error"
	}
	return "agent.event"
}

func HashArguments(args []string) string {
	sum := sha256.Sum256([]byte(strings.Join(args, "\x00")))
	return hex.EncodeToString(sum[:])
}

func Recent(path string, limit int) ([]Event, error) {
	if strings.TrimSpace(path) == "" || limit < 1 {
		return []Event{}, nil
	}
	file, err := os.Open(path)
	if errorsIsNotExist(err) {
		return []Event{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open session audit: %w", err)
	}
	defer file.Close()

	events := make([]Event, 0, limit)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("decode session audit: %w", err)
		}
		if len(events) == limit {
			copy(events, events[1:])
			events[len(events)-1] = event
		} else {
			events = append(events, event)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read session audit: %w", err)
	}
	for left, right := 0, len(events)-1; left < right; left, right = left+1, right-1 {
		events[left], events[right] = events[right], events[left]
	}
	return events, nil
}

func errorsIsNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}
