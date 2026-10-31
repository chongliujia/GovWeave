package gateway

import (
	"fmt"
	"strconv"
)

// A finding is an observation tied to an immutable capture. It carries neither
// a calibrated risk probability nor an inferred claim of legal violation.
type EvidenceFinding struct {
	ID              string `json:"id"`
	Control         string `json:"control"`
	Category        string `json:"category"`
	Result          string `json:"result"`
	Reason          string `json:"reason"`
	Source          string `json:"source"`
	DetectorVersion string `json:"detector_version,omitempty"`
	PolicyRevision  uint64 `json:"policy_revision"`
	ObjectID        string `json:"object_id,omitempty"`
}

func EvidenceFindings(bundle EvidenceBundle) []EvidenceFinding {
	findings := []EvidenceFinding{}
	object := func(kind string) string {
		for _, value := range bundle.Objects {
			if value.Kind == kind {
				return value.ID
			}
		}
		return ""
	}
	add := func(control, category, result, reason, detector, kind, source string, revision uint64) {
		findings = append(findings, EvidenceFinding{ID: bundle.ID + ":finding:" + control + ":" + category,
			Control: control, Category: category, Result: result, Reason: reason, Source: source,
			DetectorVersion: detector, PolicyRevision: revision, ObjectID: object(kind)})
	}
	r := bundle.Record
	if r.ErrorCode == "model_not_allowed" || r.ErrorCode == "tool_not_allowed" {
		add("authorization", "access_denied", "denied", r.ErrorCode, "", "request", "gateway_observation", r.PolicyRevision)
	}
	if p := r.ContentPolicy; p != nil {
		for _, rule := range p.MatchedRules {
			add("credential_egress", rule, p.Result, "credential_pattern", p.RulesetVersion, "request", "detector_observation", p.Revision)
		}
		if p.Result == "error" {
			add("credential_egress", "unknown", p.Result, "check_unavailable", p.RulesetVersion, "request", "gateway_observation", p.Revision)
		}
	}
	if p := r.OutputPolicy; p != nil {
		kind := "upstream_output"
		if r.Operation == "content.evaluate" {
			kind = "request"
		}
		for _, category := range p.MatchedCategories {
			add("sensitive_output", category, p.Result, p.Reason, p.DetectorVersion, kind, "detector_observation", p.Revision)
		}
		if p.State == "unknown" {
			add("sensitive_output", "unknown", p.Result, p.Reason, p.DetectorVersion, kind, "gateway_observation", p.Revision)
		}
	}
	if tool := r.ToolGovernance; tool != nil {
		for _, rule := range tool.Content.RuleIDs {
			add("tool_credentials", rule, tool.Decision, "credential_pattern", tool.RulesetVersion, "upstream_output", "detector_observation", tool.ToolRevision)
		}
		if p := tool.InstructionPolicy; p != nil {
			for _, rule := range p.RuleIDs {
				add("tool_instruction", rule, p.Decision, p.State, p.InstructionPolicy.Version, "upstream_output", "detector_observation", tool.ToolRevision)
			}
			if p.State == "unknown" {
				add("tool_instruction", "unknown", p.Decision, p.State, p.InstructionPolicy.Version, "upstream_output", "gateway_observation", tool.ToolRevision)
			}
		}
	}
	return findings
}

type EvidenceGraphNode struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Label      string `json:"label"`
	EvidenceID string `json:"evidence_id,omitempty"`
	ObjectID   string `json:"object_id,omitempty"`
}

type EvidenceGraphEdge struct {
	Source     string `json:"source"`
	Target     string `json:"target"`
	Relation   string `json:"relation"`
	Provenance string `json:"provenance"`
	Resolution string `json:"resolution"`
}

type EvidenceGraph struct {
	SchemaVersion       int                 `json:"schema_version"`
	RootEvidenceID      string              `json:"root_evidence_id"`
	ApplicationID       string              `json:"application_id"`
	Scope               string              `json:"scope"`
	Coverage            string              `json:"coverage"`
	HistoryMayBeMissing bool                `json:"history_may_be_missing"`
	GraphComplete       bool                `json:"graph_complete"`
	ResultTruncated     bool                `json:"result_truncated"`
	UnavailableRecords  int                 `json:"unavailable_records"`
	Nodes               []EvidenceGraphNode `json:"nodes"`
	Edges               []EvidenceGraphEdge `json:"edges"`
}

// EvidenceGraphFor reads only retained captures within the explicit application
// scope. Trace references remain caller declarations, even when both endpoints
// are retained. Shared fingerprints do not create inferred data-flow edges.
func (s *EvidenceStore) Graph(id, appID string) (EvidenceGraph, error) {
	root, err := s.Get(id, appID)
	if err != nil {
		return EvidenceGraph{}, err
	}
	g := EvidenceGraph{SchemaVersion: 1, RootEvidenceID: id, ApplicationID: appID, Scope: "same_application",
		Coverage: "retained_gateway_evidence", HistoryMayBeMissing: true, GraphComplete: false,
		Nodes: []EvidenceGraphNode{}, Edges: []EvidenceGraphEdge{}}
	bundles := []EvidenceBundle{root}
	if root.TraceID != "" {
		related, err := s.ListTrace(appID, root.TraceID, 33)
		if err != nil {
			g.UnavailableRecords++
		} else {
			// The candidate list itself is bounded. Unreadable candidates must
			// not hide the fact that older captures may have been omitted.
			g.ResultTruncated = len(related) >= 33
			for _, summary := range related {
				if summary.ID == id {
					continue
				}
				if len(bundles) == 32 {
					g.ResultTruncated = true
					break
				}
				bundle, err := s.Get(summary.ID, appID)
				if err != nil {
					g.UnavailableRecords++
					continue
				}
				bundles = append(bundles, bundle)
			}
		}
	}
	nodes := map[string]bool{}
	addNode := func(node EvidenceGraphNode) {
		if !nodes[node.ID] {
			nodes[node.ID] = true
			g.Nodes = append(g.Nodes, node)
		}
	}
	edge := func(source, target, relation, provenance, resolution string) {
		g.Edges = append(g.Edges, EvidenceGraphEdge{source, target, relation, provenance, resolution})
	}
	spans := map[string][]string{}
	for _, b := range bundles {
		call := b.ID + ":call"
		addNode(EvidenceGraphNode{ID: call, Type: "call", Label: b.Record.Operation + " · " + b.Record.Outcome, EvidenceID: b.ID})
		if b.Record.Trace != nil {
			spans[b.Record.Trace.SpanID] = append(spans[b.Record.Trace.SpanID], call)
		}
		for _, o := range b.Objects {
			addNode(EvidenceGraphNode{ID: o.ID, Type: "object", Label: o.Kind + " · " + o.ContentState, EvidenceID: b.ID, ObjectID: o.ID})
			relation := "observed_output"
			if o.Kind == "request" {
				relation = "observed_input"
			}
			if o.Kind == "upstream_request" {
				relation = "prepared_upstream_input"
			}
			if o.Kind == "released_output" {
				relation = "prepared_client_output"
			}
			if o.ContentState == "not_observed" || o.ContentState == "streaming_not_captured" {
				relation = "content_gap"
			}
			edge(call, o.ID, relation, "gateway_capture", "observed")
		}
		for _, p := range b.Policies {
			pid := b.ID + ":policy:" + p.Kind + ":" + strconv.FormatUint(p.Revision, 10)
			addNode(EvidenceGraphNode{ID: pid, Type: "policy", Label: fmt.Sprintf("%s @ %d", p.ID, p.Revision), EvidenceID: b.ID})
			edge(call, pid, "policy_snapshot", "gateway_snapshot", "observed")
		}
		for _, f := range EvidenceFindings(b) {
			addNode(EvidenceGraphNode{ID: f.ID, Type: "finding", Label: f.Control + " · " + f.Category + " · " + f.Result, EvidenceID: b.ID, ObjectID: f.ObjectID})
			edge(call, f.ID, "recorded_finding", f.Source, "observed")
			if f.ObjectID != "" {
				edge(f.ID, f.ObjectID, "assessed_object", f.Source, "observed")
			}
		}
	}
	for _, b := range bundles {
		t := b.Record.Trace
		if t == nil {
			continue
		}
		ref := func(span, relation string) {
			if span == "" {
				return
			}
			matches := spans[span]
			target, resolution := "reference:"+span, "unresolved"
			if len(matches) == 1 {
				target, resolution = matches[0], "observed"
			}
			if len(matches) > 1 {
				resolution = "ambiguous"
			}
			if resolution != "observed" {
				addNode(EvidenceGraphNode{ID: target, Type: "reference", Label: span + " · " + resolution})
			}
			edge(b.ID+":call", target, relation, "caller_declared", resolution)
		}
		ref(t.ParentSpanID, "parent")
		for _, span := range t.Links {
			ref(span, "link")
		}
		ref(t.RetryOfSpanID, "retry_of")
	}
	return g, nil
}
