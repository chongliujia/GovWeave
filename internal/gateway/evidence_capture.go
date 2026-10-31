package gateway

import (
	"encoding/json"
	"log"
)

// callEvidence exists only for an explicitly scoped capture. Its byte slices
// belong to this request and never enter the ordinary call log or diagnostics.
// A request freezes the capture configuration after its identity is rechecked.
type callEvidence struct {
	applicationID string
	payload       EvidencePayload
	finished      bool
}

func (g *Engine) beginCallEvidence(record CallRecord, request []byte) *callEvidence {
	if g.Evidence == nil {
		return nil
	}
	config := g.Evidence.Config()
	if !config.Applies(record.ApplicationID) {
		return nil
	}
	capture := &callEvidence{applicationID: record.ApplicationID, payload: EvidencePayload{
		Config: config, DeliveryState: "not_observed", Policies: []EvidencePolicySnapshot{},
		Objects: []EvidenceObjectInput{
			{Kind: "request", MediaType: "application/json", Data: request},
			{Kind: "upstream_request", MediaType: "application/json", ContentState: "not_observed"},
			{Kind: "upstream_output", MediaType: "application/json", ContentState: "not_observed"},
			{Kind: "released_output", MediaType: "application/json", ContentState: "not_observed"},
		},
	}}
	return capture
}

func (c *callEvidence) observe(kind string, data []byte) {
	if c == nil || c.finished {
		return
	}
	for i := range c.payload.Objects {
		if c.payload.Objects[i].Kind == kind {
			// These buffers are read-only after validation; canonicalization and
			// redaction allocate separate buffers. Avoid copying large envelopes.
			c.payload.Objects[i].Data = data
			c.payload.Objects[i].ContentState = ""
			return
		}
	}
}

func (c *callEvidence) response(value any) {
	if c == nil || c.finished {
		return
	}
	if data, err := json.Marshal(value); err == nil {
		// respond uses json.Encoder.Encode, including this terminal newline.
		c.observe("released_output", append(data, '\n'))
	}
}

func (c *callEvidence) policy(kind, id string, revision uint64, snapshot any) {
	if c == nil || c.finished {
		return
	}
	data, err := json.Marshal(snapshot)
	if err == nil {
		c.payload.Policies = append(c.payload.Policies, EvidencePolicySnapshot{Kind: kind, ID: id, Revision: revision, Snapshot: data})
	}
}

// Only retain the accepted controls and selected resource classification.
// Provider credentials, endpoints, grant lists and resource identifiers stay
// out of this metadata projection. The request artifact contains resource_id
// only when full content capture was explicitly enabled.
func (c *callEvidence) toolPolicy(resolved ResolvedTool) {
	if c == nil || resolved.Tool.ID == "" {
		return
	}
	c.policy("tool", resolved.Tool.ID, resolved.Tool.Revision, struct {
		ID                string             `json:"id"`
		Revision          uint64             `json:"revision"`
		SnapshotSHA256    string             `json:"snapshot_sha256"`
		OutputMode        string             `json:"output_mode"`
		RulesetVersion    string             `json:"ruleset_version"`
		DataSensitivity   string             `json:"data_sensitivity"`
		InstructionPolicy *InstructionPolicy `json:"instruction_policy,omitempty"`
		InstructionReview *InstructionReview `json:"instruction_review,omitempty"`
	}{resolved.Tool.ID, resolved.Tool.Revision, resolved.Tool.SnapshotSHA256, resolved.Tool.OutputMode,
		credentialRuleset, resolved.Resource.Sensitivity, resolved.Tool.InstructionPolicy, resolved.Resource.InstructionReview})
}

// Evidence is supplementary. A vault error never rewrites a successful audit
// commit or weakens the existing audit admission/output release gates. No
// evidence ID is advertised before storage succeeds; callers query by request
// ID and must treat unavailable evidence as unknown.
func (g *Engine) finishCallEvidence(c *callEvidence, requestID string, committed bool, delivery string) {
	if c == nil || c.finished {
		return
	}
	c.finished = true
	if !committed {
		return
	}
	// Audit.Finish normalizes timestamp and phase on its own copy. Retain that
	// exact committed copy, not an approximation with the current timestamp.
	g.Audit.mu.Lock()
	var record CallRecord
	for i := len(g.Audit.recent) - 1; i >= 0; i-- {
		candidate := g.Audit.recent[i]
		if candidate.RequestID == requestID && candidate.Phase == "finished" && candidate.ApplicationID == c.applicationID {
			record = cloneCallRecord(candidate)
			break
		}
	}
	g.Audit.mu.Unlock()
	if record.RequestID == "" {
		log.Printf("govweave: supplementary evidence could not match the committed call record; request_id=%s", requestID)
		return
	}
	c.finished = false
	if record.ContentPolicy != nil {
		if snapshot, err := g.Policies.Revision(record.ContentPolicy.Revision); err == nil {
			c.policy("input", snapshot.ID, snapshot.Revision, snapshot)
		}
	}
	if record.OutputPolicy != nil {
		if snapshot, err := g.OutputPolicies.Revision(record.OutputPolicy.Revision); err == nil {
			c.policy("output", snapshot.ID, snapshot.Revision, snapshot)
		}
	}
	c.finished = true
	c.payload.AuditCommitted, c.payload.DeliveryState = true, delivery
	if _, err := g.Evidence.Capture(record, c.payload); err != nil {
		log.Printf("govweave: supplementary evidence was not retained; request_id=%s", requestID)
	}
	// Drop payload references as soon as synchronous capture has completed.
	c.payload.Objects = nil
}
