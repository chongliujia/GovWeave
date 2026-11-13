package governance

import (
	"slices"
	"time"
)

type CoverageCounts struct {
	Requests          int    `json:"requests"`
	Finished          int    `json:"finished"`
	Unfinished        int    `json:"unfinished"`
	UpstreamAttempted int    `json:"upstream_attempted"`
	Blocked           int    `json:"blocked"`
	Failed            int    `json:"failed"`
	Traced            int    `json:"traced"`
	LastObservedAt    string `json:"last_observed_at,omitempty"`
	LastTraceID       string `json:"last_trace_id,omitempty"`
}

type CoverageRoute struct {
	ApplicationID string          `json:"application_id"`
	Operation     string          `json:"operation"`
	TargetID      string          `json:"target_id,omitempty"`
	Alias         string          `json:"alias,omitempty"`
	Configuration string          `json:"configuration"`
	Observation   string          `json:"observation"`
	InputMode     string          `json:"credential_input_mode,omitempty"`
	OutputMode    string          `json:"sensitive_output_mode,omitempty"`
	Runtime       *CoverageCounts `json:"runtime"`
	Probes        *CoverageCounts `json:"probes"`
}

type ProductCoverage struct {
	SchemaVersion       int             `json:"schema_version"`
	ProductID           string          `json:"product_id"`
	ObservedAt          string          `json:"observed_at"`
	Snapshot            SourceStamp     `json:"snapshot"`
	Selection           string          `json:"selection"`
	SampleLimit         int             `json:"sample_limit"`
	GlobalSampleSize    int             `json:"global_sample_size"`
	HistoryMayBeMissing bool            `json:"history_may_be_missing"`
	Completeness        string          `json:"completeness"`
	UnverifiedChannels  []string        `json:"unverified_channels"`
	Routes              []CoverageRoute `json:"routes"`
}

func (s *Service) Coverage(id string) (ProductCoverage, error) {
	for attempt := 0; attempt < 3; attempt++ {
		product, err := s.Products.Get(id)
		if err != nil {
			return ProductCoverage{}, err
		}
		source := capture(s.gateway)
		result := source.coverage(product, time.Now())
		current, err := s.Products.Get(id)
		if err != nil {
			return ProductCoverage{}, err
		}
		if result.Snapshot == currentStamp(s.gateway, current) {
			return result, nil
		}
	}
	return ProductCoverage{}, ErrSnapshotChanged
}

func (s sources) coverage(product Product, now time.Time) ProductCoverage {
	result := ProductCoverage{
		SchemaVersion: 1, ProductID: product.ID, ObservedAt: now.UTC().Format(time.RFC3339Nano),
		Snapshot: s.stamp(product), Selection: "product_applications_from_global_recent_100",
		SampleLimit: SampleLimit, GlobalSampleSize: len(s.audit.Records), HistoryMayBeMissing: true,
		Completeness: "not_established", Routes: []CoverageRoute{},
		UnverifiedChannels: []string{"application_ingress_egress", "agent_handoffs", "retrieval_outside_gateway", "direct_provider_egress"},
	}
	type routeKey struct{ app, operation, target string }
	indexes := map[routeKey]int{}
	add := func(key routeKey, alias, configuration string) int {
		if index, found := indexes[key]; found {
			return index
		}
		route := CoverageRoute{ApplicationID: key.app, Operation: key.operation, TargetID: key.target, Alias: alias,
			Configuration: configuration, Observation: "unavailable"}
		if s.audit.Available {
			route.Observation, route.Runtime, route.Probes = "not_observed", &CoverageCounts{}, &CoverageCounts{}
		}
		if key.operation == "chat.completions" && configuration != "unresolved" {
			route.InputMode = s.policy.Mode
			if len(s.policy.ApplicationIDs) > 0 && !slices.Contains(s.policy.ApplicationIDs, key.app) ||
				len(s.policy.ConnectionIDs) > 0 && !slices.Contains(s.policy.ConnectionIDs, key.target) {
				route.InputMode = "out_of_scope"
			}
		}
		if key.operation != "content.evaluate" && configuration != "unresolved" {
			route.OutputMode = s.outputPolicy.Mode
			if len(s.outputPolicy.ApplicationIDs) > 0 && !slices.Contains(s.outputPolicy.ApplicationIDs, key.app) {
				route.OutputMode = "out_of_scope"
			}
		}
		indexes[key] = len(result.Routes)
		result.Routes = append(result.Routes, route)
		return indexes[key]
	}
	for _, app := range s.resources.Applications {
		if !slices.Contains(product.ApplicationIDs, app.ID) {
			continue
		}
		state := func(enabled bool) string {
			if app.Revoked {
				return "revoked"
			}
			if !enabled {
				return "disabled"
			}
			return "configured"
		}
		for _, connection := range s.resources.Connections {
			if slices.Contains(app.AllowedConnections, connection.ID) {
				add(routeKey{app.ID, "chat.completions", connection.ID}, connection.Alias, state(connection.Enabled))
			}
		}
		for _, tool := range s.tools.Tools {
			for _, resource := range tool.Resources {
				if slices.Contains(resource.AllowedApplications, app.ID) {
					add(routeKey{app.ID, "tools.invoke", tool.ID}, tool.Alias, state(tool.Enabled))
					break
				}
			}
		}
		add(routeKey{app.ID, "content.evaluate", ""}, "", state(true))
	}
	if !s.audit.Available {
		return result
	}
	for _, record := range s.audit.Records {
		if !slices.Contains(product.ApplicationIDs, record.ApplicationID) {
			continue
		}
		operation, probe := record.Operation, false
		switch operation {
		case "assessment.chat.completions":
			operation, probe = "chat.completions", true
		case "assessment.tools.invoke":
			operation, probe = "tools.invoke", true
		case "chat.completions", "tools.invoke", "content.evaluate":
		default:
			continue
		}
		target := ""
		if operation == "chat.completions" {
			target = record.ConnectionID
		} else if operation == "tools.invoke" && record.ToolGovernance != nil {
			target = record.ToolGovernance.ToolID
		}
		index := add(routeKey{record.ApplicationID, operation, target}, "", "unresolved")
		route := &result.Routes[index]
		counts := route.Runtime
		if probe {
			counts = route.Probes
		} else {
			route.Observation = "observed"
		}
		counts.Requests++
		if record.Phase == "finished" {
			counts.Finished++
		} else {
			counts.Unfinished++
		}
		if record.UpstreamAttempted {
			counts.UpstreamAttempted++
		}
		if record.Outcome == "blocked" {
			counts.Blocked++
		}
		if record.Outcome == "failed" {
			counts.Failed++
		}
		if record.Trace != nil {
			counts.Traced++
		}
		observed := record.Timestamp
		if observed == "" {
			observed = record.StartedAt
		}
		stamp, stampErr := time.Parse(time.RFC3339Nano, observed)
		previous, previousErr := time.Parse(time.RFC3339Nano, counts.LastObservedAt)
		if stampErr == nil && (previousErr != nil || stamp.After(previous)) {
			counts.LastObservedAt, counts.LastTraceID = observed, ""
			if record.Trace != nil {
				counts.LastTraceID = record.Trace.TraceID
			}
		}
	}
	return result
}
