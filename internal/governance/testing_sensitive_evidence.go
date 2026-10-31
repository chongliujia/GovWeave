package governance

import (
	"encoding/json"
	"time"

	"govweave/internal/compliance"
)

// Merge only the latest run per phase, for the exact current product, plan,
// suite, rules and gateway configuration. No model I/O occurs here. A new
// running/failed/inconclusive run replaces the old evidence immediately.
func (a *ActiveTests) addOutputEvidence(product Product, source sources, input *compliance.Input) uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, plan := range a.plans {
		if plan.ProductID == product.ID {
			a.addPlanOutputEvidenceLocked(product, plan, source, input)
		}
	}
	return a.evidenceRevision
}

func (a *ActiveTests) addPlanOutputEvidenceLocked(product Product, plan TestPlan, source sources, input *compliance.Input) {
	if plan.LastError != "" {
		return
	}
	suite, err := a.Suite(plan.SuiteID, plan.SuiteVersion)
	if err != nil || suite.TargetKind != plan.TargetKind {
		return
	}
	pack, err := a.service.evaluator.PackSnapshot(product.PackID, product.PackVersion)
	if err != nil {
		return
	}
	current := TestRun{RunnerVersion: runnerFor(plan), Product: product, Plan: plan, SuiteSHA256: digestJSON(suite), GatewayRevision: source.resources.Revision, PolicyRevision: source.policy.Revision, RulePack: pack, Input: *input}
	if plan.TargetKind == "read_tool" {
		for _, tool := range source.tools.Tools {
			if tool.Alias == plan.ToolAlias {
				current.ToolID, current.ToolRevision = tool.ID, tool.Revision
			}
		}
		if current.ToolID == "" {
			return
		}
	} else {
		for _, connection := range source.resources.Connections {
			if connection.Alias == plan.ModelAlias {
				current.ConnectionID, current.ConnectionRevision = connection.ID, connection.Revision
			}
		}
		if current.ConnectionID == "" {
			return
		}
	}
	for _, phase := range []string{"pre_deployment", "operation"} {
		var latest TestRunSummary
		for _, candidate := range a.runs {
			if candidate.ProductID == product.ID && candidate.PlanID == plan.ID && candidate.Phase == phase && (latest.ID == "" || testStartedBefore(latest.StartedAt, candidate.StartedAt)) {
				latest = candidate
			}
		}
		if latest.ID == "" {
			continue
		}
		run, err := a.getLocked(latest.ID)
		if err != nil || !comparableTestRuns(current, run) {
			continue
		}
		passed, valid := outputSuiteVerdict(run)
		if !valid {
			continue
		}
		finished, err := time.Parse(time.RFC3339Nano, run.FinishedAt)
		if err != nil {
			continue
		}
		lifetime := 30 * 24 * time.Hour
		if phase == "operation" {
			lifetime = 2 * time.Duration(plan.IntervalSeconds) * time.Second
		}
		value, _ := json.Marshal(passed)
		input.Facts["testing."+outputFactPrefix(plan)+phase+".passed"] = compliance.Fact{Value: value, EvidenceID: run.ID, Source: "assessment", ObservedAt: run.FinishedAt, ExpiresAt: finished.Add(lifetime).UTC().Format(time.RFC3339Nano)}
	}
	return
}
