package governance

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"govweave/internal/gateway"
)

func coverageFixture() (Product, sources) {
	product := Product{ID: "product", ProductInput: ProductInput{Revision: 7, ApplicationIDs: []string{"app-a"}}}
	source := sources{
		resources: gateway.Snapshot{Revision: 3,
			Applications: []gateway.Application{{ID: "app-a", AllowedConnections: []string{"model-a"}}, {ID: "app-other"}},
			Connections:  []gateway.Connection{{ID: "model-a", Alias: "assistant", Enabled: true, BaseURL: "https://private-upstream.invalid"}}},
		tools: gateway.ToolSnapshot{Tools: []gateway.Tool{{ID: "tool-a", Alias: "knowledge", Enabled: true,
			Resources: []gateway.ToolResource{{ID: "private-resource", AllowedApplications: []string{"app-a"}}}}}},
		policy:       gateway.PolicySnapshot{PolicyInput: gateway.PolicyInput{Mode: "block"}},
		outputPolicy: gateway.OutputPolicySnapshot{OutputPolicyInput: gateway.OutputPolicyInput{Mode: "redact"}},
		audit:        gateway.AuditView{Available: true, Records: []gateway.CallRecord{}},
	}
	return product, source
}

func TestCoverageSeparatesRuntimeProbesAndUnknownPaths(t *testing.T) {
	product, source := coverageFixture()
	now := time.Now().UTC()
	source.audit.Records = []gateway.CallRecord{
		{ApplicationID: "app-a", ConnectionID: "model-a", Operation: "assessment.chat.completions", Phase: "finished", Outcome: "completed"},
		{ApplicationID: "app-other", ConnectionID: "model-a", Operation: "chat.completions", Phase: "finished", Outcome: "completed"},
		{ApplicationID: "app-a", Operation: "models.list", Phase: "finished"},
	}
	view := source.coverage(product, now)
	if len(view.Routes) != 3 || view.Routes[0].Observation != "not_observed" || view.Routes[0].Runtime.Requests != 0 || view.Routes[0].Probes.Requests != 1 {
		t.Fatal("probes or other applications fabricated runtime coverage", view)
	}
	if view.Completeness != "not_established" || !view.HistoryMayBeMissing || len(view.UnverifiedChannels) != 4 || view.SampleLimit != 100 || view.GlobalSampleSize != 3 {
		t.Fatal("coverage boundaries missing", view)
	}
	source.audit.Records = append(source.audit.Records,
		gateway.CallRecord{ApplicationID: "app-a", ConnectionID: "model-a", Operation: "chat.completions", Phase: "finished", Outcome: "blocked", Timestamp: now.Format(time.RFC3339Nano), Trace: &gateway.TraceContext{TraceID: strings.Repeat("a", 32)}},
		gateway.CallRecord{ApplicationID: "app-a", ConnectionID: "model-a", Operation: "chat.completions", Phase: "started", Outcome: "incomplete", StartedAt: now.Add(time.Second).Format(time.RFC3339Nano)},
		gateway.CallRecord{ApplicationID: "app-a", Operation: "tools.invoke", Phase: "finished", Outcome: "failed", UpstreamAttempted: true, ToolGovernance: &gateway.ToolGovernance{ToolID: "tool-a"}},
		gateway.CallRecord{ApplicationID: "app-a", Operation: "assessment.tools.invoke", Phase: "finished", ToolGovernance: &gateway.ToolGovernance{ToolID: "tool-a"}},
		gateway.CallRecord{ApplicationID: "app-a", Operation: "content.evaluate", Phase: "finished"},
		gateway.CallRecord{ApplicationID: "app-a", Operation: "tools.invoke", Phase: "finished", Outcome: "blocked"},
	)
	view = source.coverage(product, now)
	model, tool, content, unresolved := view.Routes[0], view.Routes[1], view.Routes[2], view.Routes[3]
	if model.Runtime.Requests != 2 || model.Runtime.Finished != 1 || model.Runtime.Unfinished != 1 || model.Runtime.Blocked != 1 || model.Runtime.Traced != 1 || model.Runtime.UpstreamAttempted != 0 || model.Runtime.LastTraceID != "" {
		t.Fatal("runtime lifecycle or most recent trace misrepresented", model)
	}
	if tool.Runtime.Requests != 1 || tool.Runtime.Failed != 1 || tool.Runtime.UpstreamAttempted != 1 || tool.Probes.Requests != 1 {
		t.Fatal("tool calls not separately accounted", tool)
	}
	if content.Runtime.Requests != 1 || content.InputMode != "" || content.OutputMode != "" || unresolved.Configuration != "unresolved" || unresolved.OutputMode != "" {
		t.Fatal("standalone checks or denied routes imply enforcement", view)
	}
	encoded, _ := json.Marshal(view)
	for _, private := range []string{"private-resource", "private-upstream", "app-other"} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("coverage leaked unneeded source data")
		}
	}
}

func TestCoverageUnavailableAndCurrentConfiguration(t *testing.T) {
	product, source := coverageFixture()
	source.audit.Available = false
	source.resources.Connections[0].Enabled = false
	source.policy.ConnectionIDs = []string{"other-model"}
	source.outputPolicy.ApplicationIDs = []string{"other-app"}
	view := source.coverage(product, time.Now())
	model := view.Routes[0]
	if model.Runtime != nil || model.Probes != nil || model.Observation != "unavailable" || model.Configuration != "disabled" || model.InputMode != "out_of_scope" || model.OutputMode != "out_of_scope" {
		t.Fatal("unavailable audit interpreted as zero or policy scope lost", model)
	}
	source.resources.Applications[0].Revoked = true
	if source.coverage(product, time.Now()).Routes[0].Configuration != "revoked" {
		t.Fatal("revoked application marked active")
	}
}

func TestCoverageServiceUsesSavedProductAndDoesNotMutate(t *testing.T) {
	fixture := setup(t)
	fixture.service.Close()
	product, err := fixture.service.Save("", fixture.input())
	if err != nil {
		t.Fatal(err)
	}
	before := currentStamp(fixture.gateway, product)
	view, err := fixture.service.Coverage(product.ID)
	if err != nil || view.Snapshot != before || view.ProductID != product.ID || len(view.Routes) != 2 || currentStamp(fixture.gateway, product) != before {
		t.Fatal("coverage read changed configuration or lost snapshot guards", view, err)
	}
	if _, err := fixture.service.Coverage("absent"); !errors.Is(err, gateway.ErrNotFound) {
		t.Fatal("missing product did not fail closed", err)
	}
}
