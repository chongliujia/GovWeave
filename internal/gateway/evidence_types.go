package gateway

import (
	"encoding/json"
	"errors"
	"regexp"
	"slices"
)

const MaxEvidenceRecords = 2048
const MaxEvidenceBytes int64 = 256 << 20
const MaxEvidenceObjectBytes = 1 << 20
const MaxEvidenceAccessBytes int64 = 8 << 20
const MaxEvidenceStreamFrames = 128

var ErrEvidenceDisabled = errors.New("evidence_disabled")
var ErrEvidenceUnavailable = errors.New("evidence_unavailable")
var ErrEvidenceNotFound = errors.New("evidence_not_found")
var ErrEvidenceExpired = errors.New("evidence_expired")
var ErrEvidenceCapacity = errors.New("evidence_capacity")
var ErrEvidenceInvalid = errors.New("invalid_evidence_request")
var ErrEvidenceContentUnavailable = errors.New("evidence_content_unavailable")

var evidenceRequestID = regexp.MustCompile(`^req_[A-Za-z0-9_-]{22}$`)
var evidenceIDPattern = regexp.MustCompile(`^ev_[A-Za-z0-9_-]{22}$`)
var evidenceApplicationID = regexp.MustCompile(`^app_[A-Za-z0-9_-]{16}$`)
var evidenceActor = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9:_-]{0,79}$`)

// EvidenceID is a reference to supplementary evidence, not proof of capture.
func EvidenceID(requestID string) string {
	if !evidenceRequestID.MatchString(requestID) {
		return ""
	}
	return "ev_" + requestID[4:]
}

type EvidenceConfig struct {
	SchemaVersion   int      `json:"schema_version"`
	Revision        uint64   `json:"revision"`
	Mode            string   `json:"mode"`
	ApplicationIDs  []string `json:"application_ids"`
	RetentionDays   int      `json:"retention_days"`
	MaxContentBytes int      `json:"max_content_bytes"`
}

func (c EvidenceConfig) Applies(applicationID string) bool {
	return c.Mode != "disabled" && evidenceApplicationID.MatchString(applicationID) &&
		slices.Contains(c.ApplicationIDs, applicationID)
}

// EvidenceObjectInput is process-local. It must never be serialized in a call
// record, diagnostic log, graph, or metadata response.
type EvidenceObjectInput struct {
	Kind         string
	MediaType    string
	Data         []byte
	ContentState string
	Stream       *EvidenceStreamInput
}

// EvidenceStreamInput carries the bounded body and incremental fingerprint for
// one stream stage. It is process-local and must not be serialized directly.
type EvidenceStreamInput struct {
	Metadata    EvidenceStream
	Bytes       int
	Data        []byte
	Fingerprint string
}

// EvidenceStream describes accepted or write-attempted frames. WrittenBytes
// counts Write return values and never establishes downstream client receipt.
type EvidenceStream struct {
	Version         string                `json:"version"`
	Scope           string                `json:"scope"`
	EndState        string                `json:"end_state"`
	FrameCount      int                   `json:"frame_count"`
	DoneSeen        bool                  `json:"done_seen"`
	FramesTruncated bool                  `json:"frames_truncated"`
	WrittenBytes    int                   `json:"written_bytes"`
	Frames          []EvidenceStreamFrame `json:"frames"`
}

type EvidenceStreamFrame struct {
	Sequence  int    `json:"sequence"`
	Offset    int    `json:"offset"`
	Bytes     int    `json:"bytes"`
	ElapsedMS int64  `json:"elapsed_ms"`
	Kind      string `json:"kind"`
}

type EvidencePolicySnapshot struct {
	Kind     string          `json:"kind"`
	ID       string          `json:"id"`
	Revision uint64          `json:"revision"`
	Snapshot json.RawMessage `json:"snapshot"`
}

// Payload freezes the capture choice made at admission. Capture does not
// reinterpret it using a subsequently edited setting.
type EvidencePayload struct {
	Config         EvidenceConfig
	Objects        []EvidenceObjectInput
	Policies       []EvidencePolicySnapshot
	AuditCommitted bool
	DeliveryState  string
}

type EvidenceObject struct {
	ID           string          `json:"id"`
	Kind         string          `json:"kind"`
	MediaType    string          `json:"media_type"`
	ContentState string          `json:"content_state"`
	Bytes        int             `json:"bytes"`
	Fingerprint  string          `json:"fingerprint,omitempty"`
	Stream       *EvidenceStream `json:"stream,omitempty"`
}

type EvidenceSummary struct {
	SchemaVersion   int    `json:"schema_version"`
	ID              string `json:"id"`
	RequestID       string `json:"request_id"`
	ApplicationID   string `json:"application_id"`
	Operation       string `json:"operation"`
	CreatedAt       string `json:"created_at"`
	ExpiresAt       string `json:"expires_at"`
	CaptureRevision uint64 `json:"capture_revision"`
	MaxContentBytes int    `json:"max_content_bytes"`
	Mode            string `json:"mode"`
	AuditCommitted  bool   `json:"audit_committed"`
	DeliveryState   string `json:"delivery_state"`
	ObjectCount     int    `json:"object_count"`
	RetainedBytes   int    `json:"retained_bytes"`
	TraceID         string `json:"trace_id,omitempty"`
}

type EvidenceBundle struct {
	EvidenceSummary
	Record    CallRecord               `json:"record"`
	Objects   []EvidenceObject         `json:"objects"`
	Policies  []EvidencePolicySnapshot `json:"policies"`
	Integrity string                   `json:"integrity"`
}

type EvidenceContent struct {
	EvidenceID     string `json:"evidence_id"`
	ObjectID       string `json:"object_id"`
	View           string `json:"view"`
	Text           string `json:"text"`
	RedactionState string `json:"redaction_state"`
}

// Access events contain fixed metadata only. A reveal_authorized event means
// release was authorized and recorded; it cannot prove client receipt.
type EvidenceAccess struct {
	SchemaVersion int    `json:"schema_version"`
	Timestamp     string `json:"timestamp"`
	Action        string `json:"action"`
	Actor         string `json:"actor"`
	EvidenceID    string `json:"evidence_id,omitempty"`
	ApplicationID string `json:"application_id,omitempty"`
	ObjectID      string `json:"object_id,omitempty"`
	View          string `json:"view,omitempty"`
	Reason        string `json:"reason,omitempty"`
	Revision      uint64 `json:"revision,omitempty"`
}
