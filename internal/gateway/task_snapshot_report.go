package gateway

import (
	"fmt"
	"strings"
)

// The human-readable report is deterministic and does not re-evaluate a model,
// re-read content, or fetch any live evidence. JSON export is the full contract.
func (v ArchivedTaskEvidence) Markdown() []byte {
	var out strings.Builder
	s, view := v.Snapshot, v.Snapshot.View
	cell := func(value string) string {
		return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\\", "\\\\", "|", "\\|", "`", "\\`", "\n", " ", "\r", " ").Replace(value)
	}
	fmt.Fprintf(&out, "# GovWeave task evidence snapshot\n\nSnapshot: `%s`  \nSaved at: `%s`  \nTrace: `%s`  \nCreated by administrator session: `%s`\n\n", s.ID, s.CreatedAt, view.TraceID, s.CreatedBy)
	fmt.Fprintf(&out, "JSON export SHA-256: `%s`  \nJSON export bytes: %d  \nView digest: `%s`\n\n", v.Summary.SHA256, v.Summary.Bytes, view.ViewSHA256)
	out.WriteString("This report preserves a bounded, non-atomic observation at save time. Evidence states below are historical, not current content availability. No prompts, responses or tool arguments are included. Findings cover successfully read retained captures only; missing evidence is unknown.\n\nLocal authentication is not external attestation or a complete inventory. Caller-declared edges do not prove data transfer or root cause. Task completion and legal compliance are not determined.\n\n## Selected applications\n\n")
	for _, id := range view.ApplicationIDs {
		fmt.Fprintf(&out, "- `%s`\n", id)
	}
	fmt.Fprintf(&out, "\n## Coverage at save time\n\n| Field | Value |\n| --- | --- |\n| Calls | %d |\n| Readable captures | %d |\n| Capture not found | %d |\n| Capture unavailable | %d |\n| Capture not loaded | %d |\n| Retained findings | %d |\n| Call limit | %d |\n| Capture-read limit | %d |\n| Result truncated | %t |\n| Audit result truncated | %t |\n| Evidence result truncated | %t |\n| Audit window saturated | %t |\n| Audit admission available | %t |\n| History may be missing | true |\n| Graph complete | false |\n| Task completion | not_determined |\n\n", view.Summary.Calls, view.Summary.Retained, view.Summary.NotFound, view.Summary.Unavailable, view.Summary.NotLoaded, view.Summary.RetainedFindings, view.CallLimit, view.EvidenceLimit, view.ResultTruncated, view.AuditResultTruncated, view.EvidenceResultTruncated, view.AuditWindowSaturated, view.AuditAvailable)
	out.WriteString("The audit source uses the global latest-1,000 request index and at most 128 matching records; capture reads use at most the newest 32 unexpired captures across the selected scope. A snapshot does not extend content retention.\n\n## Observed calls\n\n| Request | Application | Declared Agent | Timestamp | Operation | Outcome | Evidence state | Record source |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, call := range view.Calls {
		agent, timestamp, operation, outcome := "—", "—", "unknown", "unknown"
		if r := call.Record; r != nil {
			timestamp, operation, outcome = r.Timestamp, r.Operation, r.Outcome
			if r.Trace != nil && r.Trace.AgentID != "" {
				agent = r.Trace.AgentID
			}
		}
		fmt.Fprintf(&out, "| %s | %s | %s | %s | %s | %s | %s | %s |\n", cell(call.RequestID), cell(call.ApplicationID), cell(agent), cell(timestamp), cell(operation), cell(outcome), cell(call.EvidenceState), cell(call.RecordSource))
	}
	out.WriteString("\n## Findings from retained captures\n\nAn empty table is not a safety determination. Independent content evaluations do not establish that blocking or redaction was enforced.\n\n| Request | Control | Category | Result | Reason | Source | Detector | Revision | Object reference |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, call := range view.Calls {
		for _, f := range call.Findings {
			fmt.Fprintf(&out, "| %s | %s | %s | %s | %s | %s | %s | %d | %s |\n", cell(call.RequestID), cell(f.Control), cell(f.Category), cell(f.Result), cell(f.Reason), cell(f.Source), cell(f.DetectorVersion), f.PolicyRevision, cell(f.ObjectID))
		}
	}
	out.WriteString("\n## Caller-declared relationships\n\n| Source request | Target span | Visible target request | Relation | Resolution | Provenance |\n| --- | --- | --- | --- | --- | --- |\n")
	for _, e := range view.Edges {
		fmt.Fprintf(&out, "| %s | %s | %s | %s | %s | %s |\n", cell(e.SourceRequestID), cell(e.TargetSpanID), cell(e.TargetRequestID), cell(e.Relation), cell(e.Resolution), cell(e.Provenance))
	}
	out.WriteString("\nFor the exact captured records, policy observation fields and references, use the accompanying JSON export. This Markdown report is a presentation of that snapshot, not a new evaluation.\n")
	return []byte(out.String())
}
