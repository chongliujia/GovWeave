package detection

import (
	"context"

	"govweave/internal/leakage"
)

const KnownMarkerExposure = "known_marker_exposure"

type canaryPlugin struct{ stage leakage.StageDescriptor }

func (p canaryPlugin) Descriptor() Descriptor {
	return Descriptor{ID: p.stage.ID, Version: p.stage.Version, RiskType: KnownMarkerExposure}
}

func (p canaryPlugin) Evaluate(ctx context.Context, input Input) (Finding, error) {
	if err := ctx.Err(); err != nil {
		return Finding{}, err
	}
	result, err := leakage.DetectStage(p.stage.ID, input.KnownMarker, input.Content)
	if err != nil {
		return Finding{}, err
	}
	evidence := make([]Evidence, len(result.Matches))
	for i, match := range result.Matches {
		evidence[i] = Evidence{Representation: match.Representation, StartByte: match.StartByte, EndByte: match.EndByte, SpanScope: match.SpanScope, Transformations: match.Transformations, Normalized: match.Normalized}
	}
	return Finding{State: result.State, Reason: result.Reason, Evidence: evidence}, nil
}

// CanaryRegistry adapts the four offline ablation stages without changing
// production detector registration, active-test runners or historical replay.
func CanaryRegistry() (*Registry, error) {
	stages := leakage.EvaluationStages()
	plugins := make([]Plugin, len(stages))
	for i, stage := range stages {
		plugins[i] = canaryPlugin{stage: stage}
	}
	return NewRegistry(plugins...)
}
