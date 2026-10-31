package governance

import (
	"errors"
	"slices"

	"govweave/internal/gateway"
)

type testTarget struct {
	connection gateway.Connection
	tool       gateway.Tool
}

func runnerFor(plan TestPlan) string {
	if plan.TargetKind == "read_tool" {
		return toolTestRunnerVersion
	}
	return TestRunnerVersion
}

func outputFactPrefix(plan TestPlan) string {
	if plan.TargetKind == "read_tool" {
		return "tools.output."
	}
	return "output."
}

func (a *ActiveTests) resolveTestTarget(plan TestPlanInput, suite TestSuite, source sources) (testTarget, error) {
	if plan.TargetKind != suite.TargetKind {
		return testTarget{}, errors.New("plan and suite target kinds must match")
	}
	if plan.TargetKind != "read_tool" {
		resolved, err := a.service.gateway.Store.ResolveAssessment(plan.ApplicationID, plan.ModelAlias)
		if err != nil {
			return testTarget{}, err
		}
		if source.resources.Revision != resolved.PolicyRevision {
			return testTarget{}, ErrSnapshotChanged
		}
		return testTarget{connection: resolved.Connection}, nil
	}
	active := false
	for _, app := range source.resources.Applications {
		if app.ID == plan.ApplicationID && !app.Revoked {
			active = true
		}
	}
	if !active {
		return testTarget{}, gateway.ErrInvalidKey
	}
	for _, tool := range source.tools.Tools {
		if tool.Alias != plan.ToolAlias {
			continue
		}
		if !tool.Enabled {
			return testTarget{}, gateway.ErrDenied
		}
		for _, item := range suite.Cases {
			found := false
			for _, resource := range tool.Resources {
				if resource.ID == item.ResourceID {
					found = true
					// Denial probes deliberately exercise a known resource whose
					// grants may drift. Every output probe must already be granted.
					if item.Check != "tool_denied" && !slices.Contains(resource.AllowedApplications, plan.ApplicationID) {
						return testTarget{}, gateway.ErrDenied
					}
				}
			}
			if !found {
				return testTarget{}, gateway.ErrDenied
			}
		}
		return testTarget{tool: tool}, nil
	}
	return testTarget{}, gateway.ErrDenied
}
